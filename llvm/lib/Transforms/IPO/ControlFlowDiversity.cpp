//===- ControlFlowDiversity.cpp - Create run-time control flow diversity --===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This module pass creates run-time control flow diversity by cloning
// functions and randomly switching between variants at run-time.
//
//===----------------------------------------------------------------------===//

#include "llvm/Analysis/TargetTransformInfo.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/Transforms/IPO.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/Cloning.h"
#include "llvm/Transforms/Utils/Local.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

using namespace llvm;

#define DEBUG_TYPE "control-flow-diversity"

namespace {

// Should really be uint64_t
static cl::opt<unsigned> MinimumEntryCount(
  "min-entry-count",
  cl::desc("Minimum required entry count for a function to be diversified"),
  cl::init(10));

enum class ByHotness { All, IgnoreCold, OnlyHot };
static cl::opt<ByHotness> DiversifyByHotness(
  "diversify-by-hotness",
  cl::desc("Diversify functions based on hotness"),
  cl::init(ByHotness::IgnoreCold),
  cl::values(
    clEnumValN(ByHotness::All,        "all",         "Diversify all functions regardless of their hotness"),
    clEnumValN(ByHotness::IgnoreCold, "ignore-cold", "Do not diversify cold functions"),
    clEnumValN(ByHotness::OnlyHot,    "only-hot",    "Only diversify hot functions")));

enum class ByMemoryAccess { All, IgnoreNoAccess, IgnoreReadOnly};
static cl::opt<ByMemoryAccess> DiversifyByMemoryAccess(
  "diversify-by-memory-access",
  cl::desc("Diversify functions based on whether or how they access memory"),
  cl::init(ByMemoryAccess::IgnoreNoAccess),
  cl::values(
    clEnumValN(ByMemoryAccess::All,            "all",              "Diversify all functions regardless of whether they touch memory"),
    clEnumValN(ByMemoryAccess::IgnoreNoAccess, "ignore-no-access", "Do not diversify functions that do not access memory"),
    clEnumValN(ByMemoryAccess::IgnoreReadOnly, "ignore-read-only", "Do not diversify functions that only read memory")));

static cl::opt<bool> AddTracingOutput(
  "add-tracing-output",
  cl::desc("Add tracing output to function variants"),
  cl::init(false));


struct FInfo {
  Function* original;
  std::string name;
  unsigned funcIdx;

  std::vector<Function*> variants;
  GlobalVariable* fnPtrArray;
};

struct MInfo {
  std::vector<FInfo> funcs;
  std::vector<Function*> ignored;

  GlobalVariable* randFnPtrArr;
  GlobalVariable* fnDescArr;
};

class ControlFlowDiversity : public ModulePass {
public:
  static char ID;
  ControlFlowDiversity() : ModulePass(ID) {}

  void getAnalysisUsage(AnalysisUsage& AU) const override;
  bool runOnModule(Module& M) override;

private:
  MInfo analyzeModule(Module& M);

  Function* emitVariant(Function* F, StringRef origName, unsigned variantIdx);
  void convertToTrampoline(Function* F);
  void randomizeCallSites(Function* F, GlobalVariable* fnPtrArray, unsigned funcIdx);

  void removeSanitizerAttributes(Function* F);
  void removeSanitizerInstructions(Function* F);
  void removeSanitizerChecks(Function* F) {
    removeSanitizerAttributes(F);
    removeSanitizerInstructions(F);
  }

  GlobalVariable* emitPtrArray(Module& M, StringRef name, size_t size, Constant* init = nullptr);
  Constant* createFnPtrInit(Module& M, ArrayRef<Function*> replicas);
  
  StructType* emitDescTy(Module& M);
  Constant* createFnDescInit(Module& M, StructType* structTy, ArrayRef<FInfo> infos);
  GlobalVariable* emitDescArray(Module& M, StructType* structTy, size_t size, Constant* init);
  void emitRuntimeInit(Module& M, StructType* structTy, MInfo& mi);
  void addTraceStatements(Function* F);
};
} // namespace

char ControlFlowDiversity::ID = 0;
INITIALIZE_PASS(ControlFlowDiversity, "control-flow-diversity", "Control Flow Diversity",
                /* cfgOnly */ false, /* isAnalysis */ false)

ModulePass* llvm::createControlFlowDiversityPass() {
  return new ControlFlowDiversity();
}

void ControlFlowDiversity::getAnalysisUsage(AnalysisUsage& AU) const {
  AU.addRequired<TargetTransformInfoWrapperPass>();
}

bool ControlFlowDiversity::runOnModule(Module& M) {
  // Analyze module
  MInfo mi = analyzeModule(M);

  DEBUG(dbgs()
    << "Adding control flow diversity to module '" << M.getName()
    << "', instrumented/total # of functions: " << mi.funcs.size() << "/" << (mi.funcs.size() + mi.ignored.size()) << "\n"
    << "  " << MinimumEntryCount.ArgStr << "=" << MinimumEntryCount << "\n"
    << "  " << DiversifyByMemoryAccess.ArgStr << "=" << int(DiversifyByMemoryAccess.getValue()) << "\n"
    << "  " << DiversifyByHotness.ArgStr << "=" << int(DiversifyByHotness.getValue()) << "\n"
    << "Instrumented functions:"; for (auto i : mi.funcs) dbgs() << "\n  " << i.name;
    dbgs() << "\nIgnored functions:"; for (auto F : mi.ignored) dbgs() << "\n  " << F->getName();
    dbgs() << "\n");

  if (mi.funcs.empty()) {
    return false;
  }

  // Create randomized ptr array
  mi.randFnPtrArr = emitPtrArray(M, "rand_ptrs", mi.funcs.size());

  // Create first variant
  for (FInfo& i : mi.funcs) {
    Function* F = i.original;

    // 1) Create variant prototype by cloning original function
    // 2) Turn original function into trampoline
    // 3) Randomize call sites
    Function* V = emitVariant(F, i.name, 0);
    convertToTrampoline(F);
    randomizeCallSites(F, mi.randFnPtrArr, i.funcIdx);

    i.variants.push_back(V);
  }

  // Make more variants
  for (FInfo& i : mi.funcs) {
    Function* V = emitVariant(i.variants[0], i.name, 1);
    i.variants.push_back(V);
  }

  // Do not sanitize variant 0 (bookkeeping-only variant)
  for (FInfo& i : mi.funcs) {
    removeSanitizerChecks(i.variants[0]);
  }

  // Create ptr arrays.
  for (FInfo& i : mi.funcs) {
    i.fnPtrArray = emitPtrArray(M, i.name, i.variants.size(), createFnPtrInit(M, i.variants));
  }

  // Emit "metadata" for runtime randomization.
  StructType* descTy = emitDescTy(M);
  mi.fnDescArr = emitDescArray(M, descTy, mi.funcs.size(), createFnDescInit(M, descTy, mi.funcs));

  emitRuntimeInit(M, descTy, mi);

  // Emit trace output.
  if (AddTracingOutput) {
    for (FInfo& i : mi.funcs) {
      for (Function* f : i.variants) {
        addTraceStatements(f);
      }
    }
  }

  return true;
}

static bool hasMemoryAccess(const Function &F) {
  switch (DiversifyByMemoryAccess) {
    case ByMemoryAccess::All: return true;
    case ByMemoryAccess::IgnoreNoAccess: return !F.doesNotAccessMemory();
    case ByMemoryAccess::IgnoreReadOnly: return !F.onlyReadsMemory();
  }
  llvm_unreachable("unexpected enum value");
}

static bool isHotEnough(const Function &F) {
  switch (DiversifyByHotness) {
    case ByHotness::All: return true;
    case ByHotness::IgnoreCold: return !F.hasFnAttribute(llvm::Attribute::Cold);
    case ByHotness::OnlyHot: return F.hasFnAttribute(llvm::Attribute::InlineHint);
  }
  llvm_unreachable("unexpected enum value");
}

static bool shouldRandomize(const Function &F) {
  return !F.hasFnAttribute(Attribute::NoControlFlowDiversity)
      && F.getEntryCount().hasValue()
      && F.getEntryCount().getValue() >= MinimumEntryCount
      && isHotEnough(F)
      && hasMemoryAccess(F);
}

MInfo ControlFlowDiversity::analyzeModule(Module& M) {
  MInfo mi{};
  unsigned idx = 0;
  for (Function& F : M) {
    if (F.isDeclaration()) continue;
    if (shouldRandomize(F)) {
      FInfo fi { &F, F.getName(), idx++ };
      mi.funcs.push_back(fi);
    } else {
      mi.ignored.push_back(&F);
    }
  }
  auto decls = std::count_if(M.begin(), M.end(), [](Function& F) { return F.isDeclaration(); });
  assert(M.size() == decls + mi.funcs.size() + mi.ignored.size());

  return mi;
}

Function* ControlFlowDiversity::emitVariant(Function* F, StringRef origName, unsigned variantIdx) {
  // Clone function
  ValueToValueMapTy VMap;
  Function* NF = CloneFunction(F, VMap);

  // Set name and attributes
  auto idxStr = std::to_string(variantIdx);
  NF->setName(origName +"_"+ idxStr);
  NF->copyAttributesFrom(F);
  NF->setLinkage(GlobalValue::PrivateLinkage); // must be after "copyAttributesFrom" (might change visibility)
  NF->addFnAttr("cf-variant", idxStr);

  // TODO(yln): Should we remove profiling metadata from variants?
//  NF->eraseMetadata(LLVMContext::MD_prof);

  // Place just after original function
  NF->removeFromParent(); // Need to do this, otherwise next line fails.
  F->getParent()->getFunctionList().insertAfter(F->getIterator(), NF);

  return NF;
}

// deleteBody and dropAllReferences don't do the trick (they also remove function metadata)
static void dropBody(Function& F) {
  for (auto& BB : F) BB.dropAllReferences();
  while (!F.empty()) F.begin()->eraseFromParent();
}

void ControlFlowDiversity::convertToTrampoline(Function* F) {
  dropBody(*F);

  // Mark trampoline and don't sanitize
  removeSanitizerAttributes(F);
  F->addFnAttr("cf-trampoline");

  // Copy regular arguments (no var args)
  std::vector<Value*> args;
  for (auto& A : F->args()) {
    args.push_back(&A);
  }

  LLVMContext& C = F->getContext();
  BasicBlock* bb = BasicBlock::Create(C, "", F);

  // Create call to self (add artificial use); later this is replaced by randomizeCallSites
  CallInst* call = CallInst::Create(F, args, "", bb);
  call->setCallingConv(F->getCallingConv());
  call->setAttributes(F->getAttributes()); // TODO(yln): need this?
  call->setTailCall(true);

  // Return
  Value* retVal = (F->getReturnType()->isVoidTy()) ? nullptr : call;
  ReturnInst::Create(C, retVal, bb);
}

static void CallThroughPointer(CallSite cs, Value* callee) {
  assert(cs.isCall() || cs.isInvoke());

  std::vector<Value*> args(cs.arg_begin(), cs.arg_end());
  Instruction* newCall;

  if (cs.isCall()) {
    CallInst* ci = cast<CallInst>(cs.getInstruction());
    CallInst* newCi = CallInst::Create(callee, args);
    newCi->setTailCall(ci->isTailCall());
    newCall = newCi;
  } else {
    InvokeInst* ii = cast<InvokeInst>(cs.getInstruction());
    newCall = InvokeInst::Create(callee, ii->getNormalDest(), ii->getUnwindDest(), args);
  }

  CallSite newCs(newCall);
  newCs.setCallingConv(cs.getCallingConv());
  newCs.setAttributes(cs.getAttributes());

  ReplaceInstWithInst(cs.getInstruction(), newCall);
}

void ControlFlowDiversity::randomizeCallSites(Function* F, GlobalVariable* fnPtrArray, unsigned funcIdx) {
  LLVMContext& C = F->getContext();

  // Get constant pointer to right function in randomized array
  Value* indices[] = {
    ConstantInt::get(C, APInt(32, 0)), // global value is ptr
    ConstantInt::get(C, APInt(32, funcIdx))
  };
  Constant* intPtr = ConstantExpr::getGetElementPtr(nullptr, fnPtrArray, indices);

  // Cast pointee from int to appropriate function pointer
  PointerType* funcPtrPtrTy = F->getFunctionType()->getPointerTo()->getPointerTo();
  Constant* funcPtrPtr = ConstantExpr::getBitCast(intPtr, funcPtrPtrTy);

  // Replace usages
  F->removeDeadConstantUsers();
  std::vector<User*> worklist(F->user_begin(), F->user_end());

  for (auto U : worklist) {
    if (!isa<CallInst>(U) && !isa<InvokeInst>(U))
      continue;

    CallSite cs(U);

    // Load randomized function pointer
    LoadInst* funcPtr = new LoadInst(funcPtrPtr, F->getName() +"_ptr", cs.getInstruction()); // TODO(yln): should it be volatile, atomic, etc..?

// TODO(yln): Hints for the optimizer -- possible optimizations?
// Is this even useful considering we fix up trampolines at MachineInstr level?
// http://llvm.org/docs/LangRef.html#id188
// The optional !nonnull metadata must reference a single metadata name <index> corresponding to a metadata node with no entries. The existence of the !nonnull metadata on the instruction tells the optimizer that the value loaded is known to never be null. This is analogous to the nonnull attribute on parameters and return values. This metadata can only be applied to loads of a pointer type.
// The optional !dereferenceable metadata must reference a single metadata name <deref_bytes_node> corresponding to a metadata node with one i64 entry. The existence of the !dereferenceable metadata on the instruction tells the optimizer that the value loaded is known to be dereferenceable. The number of bytes known to be dereferenceable is specified by the integer value in the metadata node. This is analogous to the ‘’dereferenceable’’ attribute on parameters and return values. This metadata can only be applied to loads of a pointer type.

    if (cs.getCalledFunction() == F) {  // Used as callee (direct call)
      CallThroughPointer(cs, funcPtr);
    } else {                            // Used as argument
      // TODO(yln): Think about if we want to try opitmize, i.e., not go through the trampoline if we pass the address
      // of the original function around as a pointer value. The problem with short-circuiting the trampoline is that
      // the function could store the passed function pointer or use it multiple times (reducing randomization).
      for (Value* A : cs.args()) if (A == F) return;
      llvm_unreachable("F is not used as the callee and not as an argument");
    }
  }
}

void ControlFlowDiversity::removeSanitizerAttributes(Function* F) {
  F->removeFnAttr(Attribute::SanitizeAddress);
  F->removeFnAttr(Attribute::SanitizeMemory);
  F->removeFnAttr(Attribute::SanitizeThread);
}

static bool isNoSanitize(const Instruction* I) {
  return I->getMetadata("nosanitize") != nullptr;
}

static bool shouldRemove(const Instruction* I) {
  return I->use_empty() && isNoSanitize(I);
}

void ControlFlowDiversity::removeSanitizerInstructions(Function* F) {
  const TargetTransformInfo& TTI = getAnalysis<TargetTransformInfoWrapperPass>().getTTI(*F);
  constexpr unsigned BonusInstThreshold = 1;

  // Mark initial set of instructions for removal
  std::vector<Instruction*> removed;
  for (Instruction& I : instructions(*F)) {
    if (shouldRemove(&I)) {
      removed.push_back(&I);
    }
  }

  while (!removed.empty()) {
    // We must delete instructions in a bottom-up fashion
    Instruction* I = removed.back();
    removed.pop_back();

    // Keep a reference to the instruction operands (the instruction itself might get deleted)
    std::vector<Value*> Operands(I->op_begin(), I->op_end());

    // UBSan (and other sanitizers) adds branches to basic blocks that are terminated with an
    // unreachable instruction. The code below attempts to delete exactly those basic blocks.
    if (isa<TerminatorInst>(I)) {
      BranchInst* BI = dyn_cast<BranchInst>(I);

      if (BI && BI->isConditional()) {
        BasicBlock* TrueBB = BI->getSuccessor(0);
        BasicBlock* FalseBB = BI->getSuccessor(1);
        assert(TrueBB && FalseBB);

        TerminatorInst* TrueTI = TrueBB->getTerminator();
        TerminatorInst* FalseTI = FalseBB->getTerminator();

        // Short-circuit conditional branch if a successor block terminates with unreachable
        if (TrueTI && isa<UnreachableInst>(TrueTI) && isNoSanitize(TrueTI)) {
          BI->setCondition(ConstantInt::getFalse(F->getContext()));
        } else if (FalseTI && isa<UnreachableInst>(FalseTI) && isNoSanitize(FalseTI)) {
          BI->setCondition(ConstantInt::getTrue(F->getContext()));
        }

        // Attempt to prune BB, if it only contains the terminator
        if (TrueBB->size() == 1 || FalseBB->size() == 1) {
          simplifyCFG(BI->getParent(), TTI, BonusInstThreshold);
          simplifyCFG(TrueBB, TTI, BonusInstThreshold);
          simplifyCFG(FalseBB, TTI, BonusInstThreshold);
        }
      } else {
        // We ignore other control flow since UBSan (and other sanitizers) only inserts branches
        assert(isa<TerminatorInst>(I));
        assert(BI == nullptr || !BI->isConditional());
      }
    } else {
      I->eraseFromParent();
    }

    // Mark instructions that are no longer used
    for (Value* V : Operands) {
      Instruction* Op = dyn_cast<Instruction>(V);
      if (Op && shouldRemove(Op) && std::find(removed.begin(), removed.end(), Op) == removed.end()) {
        removed.push_back(Op);
      }
    }
  }

  for (auto BBIt = F->begin(); BBIt != F->end(); ) {
    BasicBlock& BB = *(BBIt++); // Advance iterator since SimplifyCFG might delete the current BB
    simplifyCFG(&BB, TTI, BonusInstThreshold);
  }
}

static GlobalVariable* emitArray(Module& M, StringRef name, Type* elementType, size_t size, Constant* init) {
  ArrayType* arrayType = ArrayType::get(elementType, size);
  bool constant = init != nullptr;
  if (init == nullptr) {
    init = ConstantAggregateZero::get(arrayType);
  }
  auto GV = new GlobalVariable(M, arrayType, constant, GlobalValue::PrivateLinkage, init, "cf_"+ name);
  GV->setExternallyInitialized(!constant);
  return GV;
}

static GlobalVariable* emitProbArray(Module& M, const FInfo& func) {
  IntegerType* type = Type::getInt32Ty(M.getContext());
  return emitArray(M, func.name +"_prob", type, func.variants.size(), /*init=*/ nullptr);
}

GlobalVariable* ControlFlowDiversity::emitPtrArray(Module& M, StringRef name, size_t size, Constant* init) {
  IntegerType* type = Type::getInt64Ty(M.getContext()); // ptrs are stored as 64 bit ints
  return emitArray(M, name, type, size, init);
}

Constant* ControlFlowDiversity::createFnPtrInit(Module& M, ArrayRef<Function*> variants) {
  std::vector<Constant*> elems;
  for (Function* F : variants) {
    Constant* fnPtr = ConstantExpr::getCast(Instruction::PtrToInt, F, Type::getInt64Ty(M.getContext()));
    elems.push_back(fnPtr);
  }
  ArrayType* type = ArrayType::get(Type::getInt64Ty(M.getContext()), variants.size());
  return ConstantArray::get(type, elems);
}

StructType* ControlFlowDiversity::emitDescTy(Module& M) {
  LLVMContext& C = M.getContext();
  std::vector<Type*> fields {
    Type::getInt64PtrTy(C),  // Variant pointers
    Type::getInt32PtrTy(C),  // Variant probabilities
    Type::getInt64Ty(C),     // Function entry count (profiling information)
    Type::getInt32Ty(C)      // Number of variants
  };
  return StructType::create(C, fields, "struct.cf_variant_desc");
}

Constant* ControlFlowDiversity::createFnDescInit(Module& M, StructType* structTy, ArrayRef<FInfo> infos) {
  LLVMContext& C = M.getContext();

  ConstantInt* zero = ConstantInt::get(Type::getInt32Ty(C), 0);
  Constant* indices[] = {zero, zero};

  std::vector<Constant*> elems(infos.size());
  for (const FInfo& i : infos) {
    Constant* variantArrayPtr = ConstantExpr::getGetElementPtr(nullptr, i.fnPtrArray, indices);
    Constant* probArrayPtr = ConstantExpr::getGetElementPtr(nullptr, emitProbArray(M, i), indices);
    ConstantInt* entryCount = ConstantInt::get(Type::getInt64Ty(C), i.original->getEntryCount().getValue());
    ConstantInt* variantCount = ConstantInt::get(Type::getInt32Ty(C), i.variants.size());

    std::vector<Constant*> fields {
      variantArrayPtr,  // Variant pointers
      probArrayPtr,     // Variant probabilities
      entryCount,       // Function entry count (profiling information)
      variantCount      // num_choices
    };
    elems[i.funcIdx] = ConstantStruct::get(structTy, fields);
  }
  ArrayType* type = ArrayType::get(structTy, infos.size());
  return ConstantArray::get(type, elems);
}

GlobalVariable* ControlFlowDiversity::emitDescArray(Module& M, StructType* structTy, size_t count, Constant* init) {
  ArrayType* Ty = ArrayType::get(structTy, count);
  return new GlobalVariable(M, Ty, /*isConstant*/true, GlobalValue::PrivateLinkage, init, "cf_descs");
}

static void CallRuntimeHook(Module& M, BasicBlock* bb, Constant* hook, GlobalVariable* descArr, GlobalVariable* randPtrArr, size_t size) {
  ConstantInt* const_0 = ConstantInt::get(M.getContext(), APInt(32, 0));
  Constant* indices[] = {const_0, const_0};
  Value* args[] = {
    ConstantExpr::getGetElementPtr(nullptr, descArr, indices),
    ConstantExpr::getGetElementPtr(nullptr, randPtrArr, indices),
    ConstantInt::get(Type::getInt32Ty(M.getContext()), size)
  };
  CallInst::Create(hook, args, "", bb);
}

void ControlFlowDiversity::emitRuntimeInit(Module& M, StructType* structTy, MInfo& mi) {
  LLVMContext& C = M.getContext();

  // This function is provided by the [ControlFlowRuntime.c]
  // void __cf_register(func_t* funcs, uintptr_t* rand_ptrs, uint32_t f_count)
  Constant* runtimeHook = M.getOrInsertFunction(
      "__cf_register",
      Type::getVoidTy(C),             // return type
      PointerType::get(structTy, 0),  // ptr to desc array
      PointerType::get(Type::getInt64Ty(C), 0), // ptr to randomized ptr array
      Type::getInt32Ty(C));           // function count

  // Init function
  FunctionType* initFnTy = FunctionType::get(Type::getVoidTy(C), /* isVarArg */ false);
  Function* initFn = Function::Create(initFnTy, Function::PrivateLinkage, "cf_init_runtime", &M);

  // Body
  BasicBlock* bb = BasicBlock::Create(C, "", initFn);
  CallRuntimeHook(M, bb, runtimeHook, mi.fnDescArr, mi.randFnPtrArr, mi.funcs.size());
  ReturnInst::Create(C, bb);

  // Add to global ctors
  appendToGlobalCtors(M, initFn, 0);
}

static void insertTraceFPrintf(Module& M, StringRef output, StringRef fieldName, Instruction* before) {
  // Type Definitions
  ArrayType* MessageType = ArrayType::get(IntegerType::get(M.getContext(), 8), output.size() + 2);

  // Global Variable Declarations
  GlobalVariable* gvar_array__str = new GlobalVariable(/*Module*/M,
  /*Type=*/MessageType,
  /*isConstant=*/true,
  /*Linkage=*/GlobalValue::PrivateLinkage,
  /*Initializer=*/0, // has initializer, specified below
  /*Name=*/".str_trace_" + fieldName);

  // Constant Definitions
  std::string traceOutput = (output + "\n").str();
  Constant *const_array_9 = ConstantDataArray::getString(M.getContext(), traceOutput, true);
  std::vector<Constant*> const_ptr_11_indices;
  ConstantInt* const_int32_12 = ConstantInt::get(M.getContext(), APInt(32, StringRef("0"), 10));
  const_ptr_11_indices.push_back(const_int32_12);
  const_ptr_11_indices.push_back(const_int32_12);
  Constant* const_ptr_11 = ConstantExpr::getGetElementPtr(nullptr, gvar_array__str, const_ptr_11_indices);

  // Global Variable Definitions
  gvar_array__str->setInitializer(const_array_9);

  Function* func_fprintf = M.getFunction("fprintf");
  GlobalVariable* stderr_var = M.getGlobalVariable("stderr");
  LoadInst* ptr_20 = new LoadInst(stderr_var, "", false, before);
  std::vector<Value*> int32_call_params;
  int32_call_params.push_back(ptr_20);
  int32_call_params.push_back(const_ptr_11);
  CallInst* int32_call = CallInst::Create(func_fprintf, int32_call_params, "trace_start", before);
  int32_call->setCallingConv(CallingConv::C);
  int32_call->setTailCall(false);
}

void ControlFlowDiversity::addTraceStatements(Function* F) {
  Module& M = *(F->getParent());
  Function* func_fprintf = M.getFunction("fprintf");
  if (!func_fprintf) {
    StructType *StructTy_struct__IO_FILE = M.getTypeByName("struct._IO_FILE");
    if (!StructTy_struct__IO_FILE) {
      StructTy_struct__IO_FILE = StructType::create(M.getContext(), "struct._IO_FILE");
    }
    std::vector<Type*>StructTy_struct__IO_FILE_fields;
    StructTy_struct__IO_FILE_fields.push_back(IntegerType::get(M.getContext(), 32));
    PointerType* PointerTy_2 = PointerType::get(IntegerType::get(M.getContext(), 8), 0);

    StructTy_struct__IO_FILE_fields.push_back(PointerTy_2);
    StructTy_struct__IO_FILE_fields.push_back(PointerTy_2);
    StructTy_struct__IO_FILE_fields.push_back(PointerTy_2);
    StructTy_struct__IO_FILE_fields.push_back(PointerTy_2);
    StructTy_struct__IO_FILE_fields.push_back(PointerTy_2);
    StructTy_struct__IO_FILE_fields.push_back(PointerTy_2);
    StructTy_struct__IO_FILE_fields.push_back(PointerTy_2);
    StructTy_struct__IO_FILE_fields.push_back(PointerTy_2);
    StructTy_struct__IO_FILE_fields.push_back(PointerTy_2);
    StructTy_struct__IO_FILE_fields.push_back(PointerTy_2);
    StructTy_struct__IO_FILE_fields.push_back(PointerTy_2);
    StructType *StructTy_struct__IO_marker = M.getTypeByName("struct._IO_marker");
    if (!StructTy_struct__IO_marker) {
      StructTy_struct__IO_marker = StructType::create(M.getContext(), "struct._IO_marker");
    }
    std::vector<Type*>StructTy_struct__IO_marker_fields;
    PointerType* PointerTy_3 = PointerType::get(StructTy_struct__IO_marker, 0);

    StructTy_struct__IO_marker_fields.push_back(PointerTy_3);
    PointerType* PointerTy_1 = PointerType::get(StructTy_struct__IO_FILE, 0);

    StructTy_struct__IO_marker_fields.push_back(PointerTy_1);
    StructTy_struct__IO_marker_fields.push_back(IntegerType::get(M.getContext(), 32));
    if (StructTy_struct__IO_marker->isOpaque()) {
      StructTy_struct__IO_marker->setBody(StructTy_struct__IO_marker_fields, /*isPacked=*/false);
    }


    StructTy_struct__IO_FILE_fields.push_back(PointerTy_3);
    StructTy_struct__IO_FILE_fields.push_back(PointerTy_1);
    StructTy_struct__IO_FILE_fields.push_back(IntegerType::get(M.getContext(), 32));
    StructTy_struct__IO_FILE_fields.push_back(IntegerType::get(M.getContext(), 32));
    StructTy_struct__IO_FILE_fields.push_back(IntegerType::get(M.getContext(), 64));
    StructTy_struct__IO_FILE_fields.push_back(IntegerType::get(M.getContext(), 16));
    StructTy_struct__IO_FILE_fields.push_back(IntegerType::get(M.getContext(), 8));
    ArrayType* ArrayTy_4 = ArrayType::get(IntegerType::get(M.getContext(), 8), 1);

    StructTy_struct__IO_FILE_fields.push_back(ArrayTy_4);
    StructTy_struct__IO_FILE_fields.push_back(PointerTy_2);
    StructTy_struct__IO_FILE_fields.push_back(IntegerType::get(M.getContext(), 64));
    StructTy_struct__IO_FILE_fields.push_back(PointerTy_2);
    StructTy_struct__IO_FILE_fields.push_back(PointerTy_2);
    StructTy_struct__IO_FILE_fields.push_back(PointerTy_2);
    StructTy_struct__IO_FILE_fields.push_back(PointerTy_2);
    StructTy_struct__IO_FILE_fields.push_back(IntegerType::get(M.getContext(), 64));
    StructTy_struct__IO_FILE_fields.push_back(IntegerType::get(M.getContext(), 32));
    ArrayType* ArrayTy_5 = ArrayType::get(IntegerType::get(M.getContext(), 8), 20);

    StructTy_struct__IO_FILE_fields.push_back(ArrayTy_5);
    if (StructTy_struct__IO_FILE->isOpaque()) {
      StructTy_struct__IO_FILE->setBody(StructTy_struct__IO_FILE_fields, /*isPacked=*/false);
    }


    std::vector<Type*>FuncTy_13_args;
    FuncTy_13_args.push_back(PointerTy_1);
    FuncTy_13_args.push_back(PointerTy_2);
    FunctionType* FuncTy_13 = FunctionType::get(
      /*Result=*/IntegerType::get(M.getContext(), 32),
      /*Params=*/FuncTy_13_args,
      /*isVarArg=*/true);

    func_fprintf = Function::Create(
    /*Type=*/FuncTy_13,
    /*Linkage=*/GlobalValue::ExternalLinkage,
    /*Name=*/"fprintf", &M); // (external, no body)
    func_fprintf->setCallingConv(CallingConv::C);

    new GlobalVariable(/*Module=*/M,
    /*Type=*/PointerTy_1,
    /*isConstant=*/false,
    /*Linkage=*/GlobalValue::ExternalLinkage,
    /*Initializer=*/0,
    /*Name=*/"stderr");
  }

  std::string FName = F->getName();
  BasicBlock &label_entry = F->getEntryBlock();
  Instruction *First = label_entry.getFirstNonPHI();
  insertTraceFPrintf(M, "entered "+ FName, "enter_"+ FName, First);

  // Iterate through all instructions and put trace statements for return sites.
  for (auto& BB : *F) {
    for (auto& I : BB) {
      CallSite CS(&I);
      if (CS.isCall() || CS.isInvoke()) {
        IntToPtrInst* ptrCast = dyn_cast<IntToPtrInst>(CS.getCalledValue());
        if (!ptrCast) continue;
        LoadInst* load = dyn_cast<LoadInst>(ptrCast->getOperand(0));
        if (!load) continue;
        ConstantExpr* gep = dyn_cast<ConstantExpr>(load->getOperand(0));
        if (!gep || gep->getNumOperands() != 3) continue;
        GlobalVariable* var = dyn_cast<GlobalVariable>(gep->getOperand(0));
        if (var->getName() != "cf_rand_ptrs") continue;

        insertTraceFPrintf(M, "returned to "+ FName, "return_"+ FName, I.getNextNode());
      }
    }
  }
}
