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


//// Should really be uint64_t
//static cl::opt<unsigned> MinimumEntryCount(
//  "min-entry-count",
//  cl::desc("Minimum required entry count for a function to be diversified"),
//  cl::init(10));

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


namespace {
constexpr const char* SanCovFnPrefix = "__sanitizer_cov_";
constexpr const char* SanCovVarPrefix = "__sancov_";

struct FInfo {
  Function* const Original;
  const std::string Name;
  const unsigned Index;

  Function* Trampoline;
  std::vector<Function*> Variants;
  GlobalVariable* VariantArray;
};

struct MInfo {
  std::vector<FInfo> Fns;
  std::vector<Function*> IgnoredFns;

  GlobalVariable* RandPtrArray;
};

class ControlFlowDiversity : public ModulePass {
public:
  static char ID;
  ControlFlowDiversity() : ModulePass(ID) {}

  void getAnalysisUsage(AnalysisUsage& AU) const override;
  bool runOnModule(Module& M) override;

private:
  MInfo analyzeModule(Module& M);

  void createTrampoline(FInfo& I, GlobalVariable* RandPtrArray);
  void randomizeCallSites(const FInfo& I, GlobalVariable* RandPtrArray);
  void createVariant(FInfo& I);
  void removeSanitizerAttributes(Function* F);
  void removeSanitizerChecks(Function* F, bool removeSanCov);

  GlobalVariable* emitPtrArray(Module& M, StringRef name, size_t size, Constant* init = nullptr);
  Constant* createFnPtrInit(Module& M, ArrayRef<Function*> variants);

  void emitRuntimeMetadata(Module& M, MInfo& I);
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
    << "', instrumented/total # of functions: " << mi.Fns.size() << "/" << (mi.Fns.size() + mi.IgnoredFns.size()) << "\n"
//    << "  " << MinimumEntryCount.ArgStr << "=" << MinimumEntryCount << "\n"
    << "  " << DiversifyByMemoryAccess.ArgStr << "=" << int(DiversifyByMemoryAccess.getValue()) << "\n"
    << "  " << DiversifyByHotness.ArgStr << "=" << int(DiversifyByHotness.getValue()) << "\n"
    << "Instrumented functions:"; for (auto i : mi.Fns) dbgs() << "\n  " << i.Name;
    dbgs() << "\nIgnored functions:"; for (auto F : mi.IgnoredFns) dbgs() << "\n  " << F->getName();
    dbgs() << "\n");

  if (mi.Fns.empty()) {
    return false;
  }

  // Create randomized ptr array
  mi.RandPtrArray = emitPtrArray(M, "rand_ptrs", mi.Fns.size());

  // Create trampoline, randomize call sites, make first variant
  for (FInfo& i : mi.Fns) {
    createTrampoline(i, mi.RandPtrArray);
    randomizeCallSites(i, mi.RandPtrArray);
  }

  // Create more variants
  // 0) Coverage and sanitization (converted from original)
  // 1) Coverage only
  // 2) None
  for (FInfo& i : mi.Fns) {
    createVariant(i); createVariant(i);
    removeSanitizerChecks(i.Variants[1], /* removeSanCov */ false);
    removeSanitizerChecks(i.Variants[2], /* removeSanCov */ true);
  }

  // Create ptr arrays.
  for (FInfo& i : mi.Fns) {
    i.VariantArray = emitPtrArray(M, i.Name, i.Variants.size(), createFnPtrInit(M, i.Variants));
  }

  // Emit metadata for runtime randomization
  emitRuntimeMetadata(M, mi);

  // Emit trace output.
  if (AddTracingOutput) {
    for (FInfo& i : mi.Fns) {
      for (Function* f : i.Variants) {
        addTraceStatements(f);
      }
    }
  }

  return true;
}

static bool hasMemoryAccess(const Function& F) {
  switch (DiversifyByMemoryAccess) {
    case ByMemoryAccess::All: return true;
    case ByMemoryAccess::IgnoreNoAccess: return !F.doesNotAccessMemory();
    case ByMemoryAccess::IgnoreReadOnly: return !F.onlyReadsMemory();
  }
  llvm_unreachable("unexpected enum value");
}

static bool isHotEnough(const Function& F) {
  switch (DiversifyByHotness) {
    case ByHotness::All: return true;
    case ByHotness::IgnoreCold: return !F.hasFnAttribute(llvm::Attribute::Cold);
    case ByHotness::OnlyHot: return F.hasFnAttribute(llvm::Attribute::InlineHint);
  }
  llvm_unreachable("unexpected enum value");
}

static bool shouldRandomize(const Function& F) {
  return !F.hasFnAttribute(Attribute::NoControlFlowDiversity)
      && !F.getName().contains(".module_ctor")
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
      mi.Fns.push_back(fi);
    } else {
      mi.IgnoredFns.push_back(&F);
    }
  }
  auto decls = std::count_if(M.begin(), M.end(), [](Function& F) { return F.isDeclaration(); });
  assert(M.size() == decls + mi.Fns.size() + mi.IgnoredFns.size());

  return mi;
}

static LoadInst* loadVariantPtr(const FInfo& I, GlobalVariable* RandPtrArray, IRBuilder<>& B) {
  auto* F = I.Original;

  // Get constant pointer to right function in randomized array
  auto* Int32Ty = Type::getInt32Ty(F->getContext());
  Constant* Indices[] = {
      ConstantInt::get(Int32Ty, 0),   // global value is ptr
      ConstantInt::get(Int32Ty, I.Index)
  };
  auto* Ptr = ConstantExpr::getGetElementPtr(nullptr, RandPtrArray, Indices);

  // Cast to appropriate function pointer
  auto* FuncPtrPtrTy = F->getFunctionType()->getPointerTo()->getPointerTo();
  auto* FuncPtrPtr = ConstantExpr::getBitCast(Ptr, FuncPtrPtrTy);

  return B.CreateLoad(FuncPtrPtr, I.Name +"_ptr");

// TODO(yln): should it be volatile, atomic, etc..?
// TODO(yln): Hints for the optimizer -- possible optimizations?
// Is this even useful considering we fix up trampolines at MachineInstr level?
// http://llvm.org/docs/LangRef.html#id188
// The optional !nonnull metadata must reference a single metadata name <index> corresponding to a metadata node with no entries. The existence of the !nonnull metadata on the instruction tells the optimizer that the value loaded is known to never be null. This is analogous to the nonnull attribute on parameters and return values. This metadata can only be applied to loads of a pointer type.
// The optional !dereferenceable metadata must reference a single metadata name <deref_bytes_node> corresponding to a metadata node with one i64 entry. The existence of the !dereferenceable metadata on the instruction tells the optimizer that the value loaded is known to be dereferenceable. The number of bytes known to be dereferenceable is specified by the integer value in the metadata node. This is analogous to the ‘’dereferenceable’’ attribute on parameters and return values. This metadata can only be applied to loads of a pointer type.
}

static void createTrampolineBody(FInfo &I, GlobalVariable* RandPtrArray) {
  auto* F = I.Original;

  std::vector<Value*> Args;
  for (auto& A : I.Trampoline->args()) {
    A.setName((F->arg_begin() + A.getArgNo())->getName());
    Args.push_back(&A);
  }

  auto* BB = BasicBlock::Create(F->getContext(), "", I.Trampoline);
  IRBuilder<> B(BB);

  auto* VarPtr = loadVariantPtr(I, RandPtrArray, B);
  auto* Call = B.CreateCall(VarPtr, Args);
  Call->setCallingConv(F->getCallingConv());
  Call->setTailCallKind(CallInst::TCK_MustTail);

  auto* RetVal = F->getReturnType()->isVoidTy() ? nullptr : Call;
  B.CreateRet(RetVal);
}

static void setVariantName(Function *F, StringRef Name, unsigned VariantIndex) {
  auto Index = std::to_string(VariantIndex);
  F->setName(Name +"_"+ Index);
  F->addFnAttr("cf-variant", Index);
}

void ControlFlowDiversity::createTrampoline(FInfo &I, GlobalVariable* RandPtrArray) {
  auto* F = I.Original;
  auto* NF = Function::Create(F->getFunctionType(), F->getLinkage());
  I.Trampoline = NF;

  NF->takeName(F);
  NF->copyAttributesFrom(F);
  removeSanitizerAttributes(NF);
  NF->addFnAttr("cf-trampoline");
  createTrampolineBody(I, RandPtrArray);
  F->getParent()->getFunctionList().insert(F->getIterator(), NF);

  // Convert original function into first variant
  setVariantName(F, I.Name, 0);
  F->setLinkage(GlobalValue::PrivateLinkage);
  I.Variants.push_back(F);
}

static bool isSanCovUser(const User* U, unsigned Level = 5) {
  if (U->getName().startswith(SanCovVarPrefix))
    return true;
  auto Recurse = [Level](const User *U) { return isSanCovUser(U, Level - 1); };
  return Level > 0 && std::any_of(U->user_begin(), U->user_end(), Recurse);
}

// See [Value::replaceUsesExceptBlockAddr] for algorithm template
void ControlFlowDiversity::randomizeCallSites(const FInfo& I, GlobalVariable* RandPtrArray) {
  auto* F = I.Original;
//  F->removeDeadConstantUsers(); // TODO(yln): needed?

  SmallPtrSet<Constant*, 8> Constants;
  auto UI = F->use_begin(), E = F->use_end();
  while (UI != E) {
    auto& Use = *UI++;
    auto* User = Use.getUser();

    if (isa<BlockAddress>(User) || isSanCovUser(User))
      continue;

    if (auto CS = CallSite(User)) {
      IRBuilder<> B(CS.getInstruction());
      auto* VarPtr = loadVariantPtr(I, RandPtrArray, B);
      CS.setCalledFunction(VarPtr);
    } else if (isa<Constant>(User) && !isa<GlobalValue>(User)) {
      Constants.insert(cast<Constant>(User));
    } else {
      Use.set(I.Trampoline);
    }
  }

  for (auto* C : Constants) {
    C->handleOperandChange(F, I.Trampoline);
  }
}

void ControlFlowDiversity::createVariant(FInfo& I) {
  auto VariantNo = I.Variants.size();

  // Clone function
  ValueToValueMapTy VMap;
  auto* NF = CloneFunction(I.Original, VMap);
  setVariantName(NF, I.Name, VariantNo);

  // Place after previous variant
  auto* F = I.Variants[VariantNo - 1];
  NF->removeFromParent(); // Need to do this, otherwise next line fails
  F->getParent()->getFunctionList().insertAfter(F->getIterator(), NF);

  I.Variants.push_back(NF);
}

void ControlFlowDiversity::removeSanitizerAttributes(Function* F) {
  F->removeFnAttr(Attribute::SanitizeAddress);
  F->removeFnAttr(Attribute::SanitizeHWAddress);
  F->removeFnAttr(Attribute::SanitizeMemory);
  F->removeFnAttr(Attribute::SanitizeThread);
  F->removeFnAttr(Attribute::SafeStack);
}

static bool isNoSanitize(const Instruction* I) {
  return I->getMetadata("nosanitize") != nullptr;
}

static bool hasSanCovOp(const Value* V, unsigned Level = 5) {
  if (V->getName().startswith(SanCovVarPrefix) ||
      V->getName().startswith(SanCovFnPrefix))
    return true;
  auto Recurse = [Level](const Value *V) { return hasSanCovOp(V, Level - 1); };
  auto* U = dyn_cast<User>(V);
  return Level > 0 && U && std::any_of(U->op_begin(), U->op_end(), Recurse);
}

static bool shouldRemove(const Instruction* I, bool removeSanCov) {
  if (!I->use_empty()) return false;
  return hasSanCovOp(I) ? removeSanCov : isNoSanitize(I);
}

static void removeSanitizerInstructions(Function* F, const TargetTransformInfo& TTI, bool removeSanCov) {
  constexpr unsigned BonusInstThreshold = 1;

  // Mark initial set of instructions for removal
  std::vector<Instruction*> removed;
  for (Instruction& I : instructions(*F)) {
    if (shouldRemove(&I, removeSanCov)) {
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
      if (Op && shouldRemove(Op, removeSanCov) && std::find(removed.begin(), removed.end(), Op) == removed.end()) {
        removed.push_back(Op);
      }
    }
  }

  for (auto BBIt = F->begin(); BBIt != F->end(); ) {
    BasicBlock& BB = *(BBIt++); // Advance iterator since SimplifyCFG might delete the current BB
    simplifyCFG(&BB, TTI, BonusInstThreshold);
  }
}

void ControlFlowDiversity::removeSanitizerChecks(Function* F, bool removeSanCov) {
  auto& TTI = getAnalysis<TargetTransformInfoWrapperPass>().getTTI(*F);
  removeSanitizerAttributes(F);
  removeSanitizerInstructions(F, TTI, removeSanCov);
}

static GlobalVariable* emitArray(Module& M, StringRef name, Type* elementType, size_t size, Constant* init) {
  ArrayType* arrayType = ArrayType::get(elementType, size);
  bool constant = true;
  if (init == nullptr) {
    init = ConstantAggregateZero::get(arrayType);
    constant = false;
  }
  auto GV = new GlobalVariable(M, arrayType, constant, GlobalValue::PrivateLinkage, init, "__cf_gen_"+ name);
  GV->setExternallyInitialized(!constant);
  return GV;
}

// TODO(yln): different array functions don't do much anymore. Inline!
static GlobalVariable* emitProbArray(Module& M, const FInfo& func) {
  IntegerType* type = Type::getInt32Ty(M.getContext());
  return emitArray(M, func.Name +"_prob", type, func.Variants.size(), /*init=*/ nullptr);
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

static StructType* createDescTy(Module &M) {
  auto& C = M.getContext();
  Type* Fields[] {
    Type::getInt64PtrTy(C), // Variant pointers
    Type::getInt32PtrTy(C), // Variant probabilities
    Type::getInt64Ty(C),    // Function entry count (profiling information)
    Type::getInt32Ty(C)     // Number of variants
  };
  return StructType::create(C, Fields, "struct.cf_desc");
}

static Constant* createDescInit(Module& M, StructType* DescTy, ArrayRef<FInfo> Funcs) {
  auto& C = M.getContext();
  auto* Zero = ConstantInt::get(Type::getInt32Ty(C), 0);
  Constant* Indices[]{Zero, Zero};

  std::vector<Constant*> Elems(Funcs.size());
  for (const FInfo& I : Funcs) {
    auto* VariantArrayPtr = ConstantExpr::getGetElementPtr(nullptr, I.VariantArray, Indices);
    auto* ProbArrayPtr = ConstantExpr::getGetElementPtr(nullptr, emitProbArray(M, I), Indices);
    auto* entryCount = ConstantInt::get(Type::getInt64Ty(C), 0 /* no profile data */);
    auto* VariantCount = ConstantInt::get(Type::getInt32Ty(C), I.Variants.size());

    Constant* Fields[]{VariantArrayPtr, ProbArrayPtr, entryCount, VariantCount};
    auto* Elem = ConstantStruct::get(DescTy, Fields);
    Elems[I.Index] = Elem;
  }
  auto* Ty = ArrayType::get(DescTy, Funcs.size());
  return ConstantArray::get(Ty, Elems);
}

static void createModuleCtor(Module& M, StructType* DescTy, GlobalVariable* DescArray, MInfo& I) {
  auto& C = M.getContext();
  auto* Int32Ty = Type::getInt32Ty(C);
  auto* Int64Ty = Type::getInt64Ty(C);
  auto* VoidTy = Type::getVoidTy(C);

  // This function is provided by the [ControlFlowRuntime.c]
  // void __cf_register(func_t* funcs, uintptr_t* rand_ptrs, uint32_t f_count)
  auto* Hook = M.getOrInsertFunction(
      "__cf_register",
      VoidTy, // Return type
      DescTy->getPointerTo(), Int64Ty->getPointerTo(), Int32Ty); // Arg types

  // Module ctor
  auto* CtorTy = FunctionType::get(VoidTy, /* isVarArg */ false);
  auto* Ctor = Function::Create(CtorTy, GlobalValue::PrivateLinkage, "cf.module_ctor", &M);
  auto* BB = BasicBlock::Create(C, "", Ctor);

  // Arguments
  auto* Zero = ConstantInt::get(Int32Ty, 0);
  Constant* Indices[]{Zero, Zero};
  Value* Args[] {
      ConstantExpr::getGetElementPtr(nullptr, DescArray, Indices),
      ConstantExpr::getGetElementPtr(nullptr, I.RandPtrArray, Indices),
      ConstantInt::get(Int32Ty, I.Fns.size())
  };

  // Body
  IRBuilder<> B(BB);
  B.CreateCall(Hook, Args);
  B.CreateRetVoid();

  // Add to list of ctors
  appendToGlobalCtors(M, Ctor, /* Priority */ 0);
}

void ControlFlowDiversity::emitRuntimeMetadata(Module& M, MInfo& I) {
  auto* Ty = createDescTy(M);
  auto* Init = createDescInit(M, Ty, I.Fns);
  auto* Array = emitArray(M, "descs", Ty, I.Fns.size(), Init);
  createModuleCtor(M, Ty, Array, I);
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
        if (var->getName() != "__cf_gen_rand_ptrs") continue;

        insertTraceFPrintf(M, "returned to "+ FName, "return_"+ FName, I.getNextNode());
      }
    }
  }
}
