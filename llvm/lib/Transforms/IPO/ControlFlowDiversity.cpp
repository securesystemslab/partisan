//===- ControlFlowDiversity.cpp - Create run-time control flow diversity --===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This module pass enables control-flow diversity.
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
constexpr const char* CtorName = "cf.module_ctor";

struct FInfo {
  Function* const Original;
  const std::string Name;

  Function* Trampoline;
  std::vector<Function*> Variants;
  GlobalVariable* RandLoc;
};

struct MInfo {
  std::vector<FInfo> Fns;
  std::vector<Function*> IgnoredFns;
};

class ControlFlowDiversity : public ModulePass {
public:
  static char ID;
  ControlFlowDiversity() : ModulePass(ID) {}

  void getAnalysisUsage(AnalysisUsage& AU) const override;
  bool runOnModule(Module& M) override;

private:
  MInfo analyzeModule(Module& M);
  void createRandLocation(Module& M, FInfo& I);
  void createTrampoline(FInfo& I);
  void randomizeCallSites(const FInfo& I);
  void createVariant(FInfo& I);
  void removeSanitizerAttributes(Function* F);
  void removeSanitizerChecks(Function* F);
  StructType* createDescTy(Module& M);
  void emitMetadata(Module& M, FInfo& I, StructType* DescTy);
  void createModuleCtor(Module &M, StructType *DescTy);
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
  ModulePass::getAnalysisUsage(AU);
}

bool ControlFlowDiversity::runOnModule(Module& M) {
  // Analyze module
  MInfo MI = analyzeModule(M);

  DEBUG(dbgs()
    << "Adding control flow diversity to module '" << M.getName()
    << "', instrumented/total # of functions: " << MI.Fns.size() << "/" << (MI.Fns.size() + MI.IgnoredFns.size()) << "\n"
//    << "  " << MinimumEntryCount.ArgStr << "=" << MinimumEntryCount << "\n"
    << "  " << DiversifyByMemoryAccess.ArgStr << "=" << int(DiversifyByMemoryAccess.getValue()) << "\n"
    << "  " << DiversifyByHotness.ArgStr << "=" << int(DiversifyByHotness.getValue()) << "\n"
    << "Instrumented functions:"; for (auto I : MI.Fns) dbgs() << "\n  " << I.Name;
    dbgs() << "\nIgnored functions:"; for (auto F : MI.IgnoredFns) dbgs() << "\n  " << F->getName();
    dbgs() << "\n");

  if (MI.Fns.empty())
    return false;

  // Create trampoline, make first variant, randomize call sites
  for (auto& I : MI.Fns) {
    createRandLocation(M, I);
    createTrampoline(I);
    randomizeCallSites(I);
  }

  // Create more variants
  for (auto& I : MI.Fns) {
    // 0) Coverage (converted from original), cov only added to variant 0
    // 1) Sanitization
    // 2) Fast
    createVariant(I); createVariant(I);
    removeSanitizerChecks(I.Variants[0]);
    removeSanitizerChecks(I.Variants[2]);
  }

  auto* DescTy = createDescTy(M);
  // Create variant metadata
  for (auto& I : MI.Fns) {
    emitMetadata(M, I, DescTy);
  }

  // Create module ctor to register metadata with the runtime
  createModuleCtor(M, DescTy);

  // Emit trace output.
  if (AddTracingOutput) {
    for (auto& I : MI.Fns) {
      for (auto* F : I.Variants) {
        addTraceStatements(F);
      }
    }
  }

  return true;
}

template<class Predicate>
static bool containsOperand(const Value *V, Predicate Pred, unsigned Level = 5) {
  if (Pred(V))
    return true;
  auto Recurse = [Level, Pred](const Value* V) {
    return containsOperand(V, Pred, Level - 1);
  };
  auto* U = dyn_cast<User>(V);
  return Level > 0 && U && std::any_of(U->op_begin(), U->op_end(), Recurse);
}

static bool isModuleCtor(const Function& F) {
  auto* GV = F.getParent()->getGlobalVariable("llvm.global_ctors");
  return GV && containsOperand(GV, [&F](const Value* V) {
    return V == &F;
  });
}

static bool isHotEnough(const Function& F) {
  switch (DiversifyByHotness) {
    case ByHotness::All: return true;
    case ByHotness::IgnoreCold: return !F.hasFnAttribute(llvm::Attribute::Cold);
    case ByHotness::OnlyHot: return F.hasFnAttribute(llvm::Attribute::InlineHint);
  }
  llvm_unreachable("unexpected enum value");
}

static bool hasMemoryAccess(const Function& F) {
  switch (DiversifyByMemoryAccess) {
    case ByMemoryAccess::All: return true;
    case ByMemoryAccess::IgnoreNoAccess: return !F.doesNotAccessMemory();
    case ByMemoryAccess::IgnoreReadOnly: return !F.onlyReadsMemory();
  }
  llvm_unreachable("unexpected enum value");
}

static bool shouldRandomize(const Function& F) {
  return !F.hasFnAttribute(Attribute::NoControlFlowDiversity)
      && !F.doesNotReturn()
      && !isModuleCtor(F)
      && isHotEnough(F)
      && hasMemoryAccess(F);
}

MInfo ControlFlowDiversity::analyzeModule(Module& M) {
  MInfo MI{};
  for (Function& F : M) {
    if (F.isDeclaration()) continue;
    if (shouldRandomize(F)) {
      FInfo I{&F, F.getName()};
      MI.Fns.push_back(I);
    } else {
      MI.IgnoredFns.push_back(&F);
    }
  }
  auto Decls = std::count_if(M.begin(), M.end(), [](Function &F) {
    return F.isDeclaration();
  });
  assert(M.size() == Decls + MI.Fns.size() + MI.IgnoredFns.size());

  return MI;
}

static Type* getPtrTy(const Module& M) {
  auto Bits = M.getDataLayout().getPointerSizeInBits();
  return Type::getIntNTy(M.getContext(), Bits); // Pointers are stored as ints
}

void ControlFlowDiversity::createRandLocation(Module& M, FInfo& I) {
  auto* Comdat = I.Original->getComdat();
  auto* Ty = getPtrTy(M);
  auto isConstant = false;
  auto Linkage = Comdat ? GlobalValue::LinkOnceODRLinkage
                        : GlobalValue::PrivateLinkage;
  auto* Init = Constant::getNullValue(Ty);
  auto Name = "__cf_gen_randloc." + I.Name;
  auto* GV = new GlobalVariable(M, Ty, isConstant, Linkage, Init, Name);
  GV->setExternallyInitialized(true);
  GV->setComdat(Comdat);
  I.RandLoc = GV;
}

static LoadInst* loadVariantPtr(const FInfo& I, IRBuilder<>& B) {
  auto* PtrTy = I.Original->getFunctionType()->getPointerTo()->getPointerTo();
  auto* Ptr = B.CreateBitCast(I.RandLoc, PtrTy);
  return B.CreateLoad(Ptr, I.Name +"_ptr");

// TODO(yln): should it be volatile, atomic, etc..?
// Hints for the optimizer -- possible optimizations?
// Is this even useful considering we fix up trampolines at MachineInstr level?
// http://llvm.org/docs/LangRef.html#id188
// The optional !nonnull metadata must reference a single metadata name <index> corresponding to a metadata node with no entries. The existence of the !nonnull metadata on the instruction tells the optimizer that the value loaded is known to never be null. This is analogous to the nonnull attribute on parameters and return values. This metadata can only be applied to loads of a pointer type.
// The optional !dereferenceable metadata must reference a single metadata name <deref_bytes_node> corresponding to a metadata node with one i64 entry. The existence of the !dereferenceable metadata on the instruction tells the optimizer that the value loaded is known to be dereferenceable. The number of bytes known to be dereferenceable is specified by the integer value in the metadata node. This is analogous to the ‘’dereferenceable’’ attribute on parameters and return values. This metadata can only be applied to loads of a pointer type.
}

static void createTrampolineBody(FInfo &I) {
  auto* F = I.Original;

  std::vector<Value*> Args;
  for (auto& A : I.Trampoline->args()) {
    A.setName((F->arg_begin() + A.getArgNo())->getName());
    Args.push_back(&A);
  }

  auto* BB = BasicBlock::Create(F->getContext(), "", I.Trampoline);
  IRBuilder<> B(BB);

  auto* VarPtr = loadVariantPtr(I, B);
  auto* Call = B.CreateCall(VarPtr, Args);
  Call->setCallingConv(F->getCallingConv());
  Call->setAttributes(F->getAttributes());
  Call->setTailCallKind(CallInst::TCK_MustTail);

  auto* RetVal = F->getReturnType()->isVoidTy() ? nullptr : Call;
  B.CreateRet(RetVal);
}

static void setVariantName(Function* F, StringRef Name, unsigned VariantNo) {
  auto N = std::to_string(VariantNo);
  F->setName(Name +"_"+ N);
  F->addFnAttr("cf-variant", N);
}

void ControlFlowDiversity::createTrampoline(FInfo& I) {
  auto* F = I.Original;
  auto* NF = Function::Create(F->getFunctionType(), F->getLinkage());
  I.Trampoline = NF;

  NF->takeName(F);
  NF->copyAttributesFrom(F);
  removeSanitizerAttributes(NF);
  NF->addFnAttr("cf-trampoline");
  NF->setComdat(F->getComdat());
  createTrampolineBody(I);
  F->getParent()->getFunctionList().insert(F->getIterator(), NF);

  // Convert original function into first variant
  F->setLinkage(GlobalValue::PrivateLinkage);
  setVariantName(F, I.Name, 0);
  I.Variants.push_back(F);
}

static bool isCoverageVarInit(const User* U, unsigned Level = 5) {
  if (U->getName().startswith(SanCovVarPrefix))
    return true;
  auto Recurse = [Level](const User* U) { return isCoverageVarInit(U, Level - 1); };
  return Level > 0 && std::any_of(U->user_begin(), U->user_end(), Recurse);
}

static bool isCoverageInst(const Instruction* I) {
  return I->use_empty() && containsOperand(I, [](const Value* V) {
    return V->getName().startswith(SanCovVarPrefix)
        || V->getName().startswith(SanCovFnPrefix);
  });
}

static bool isCoverageInstOperand(const Value* V) {
  while (!isa<Instruction>(V) && V->hasOneUse()) {
    V = *V->user_begin();
  }
  auto* I = dyn_cast<Instruction>(V);
  return I && isCoverageInst(I);
}

// See [Value::replaceUsesExceptBlockAddr] for algorithm template
void ControlFlowDiversity::randomizeCallSites(const FInfo& I) {
  auto* F = I.Original;
//  F->removeDeadConstantUsers(); // TODO(yln): needed?

  SmallPtrSet<Constant*, 8> Constants;
  for (auto UI = F->use_begin(), E = F->use_end(); UI != E;) {
    auto& U = *UI++; // Advance iterator since we might remove this use

    if (auto CS = CallSite(U.getUser())) {
      if (CS.getCalledFunction() == F) {
        IRBuilder<> B(CS.getInstruction());
        auto* VarPtr = loadVariantPtr(I, B);
        CS.setCalledFunction(VarPtr);
        continue;
      }
    }
    if (auto* C = dyn_cast<Constant>(U.getUser())) {
      if (!isa<GlobalValue>(C)) {
        if (!isa<BlockAddress>(C) &&
            !isCoverageVarInit(C) && !isCoverageInstOperand(C))
          Constants.insert(C);
        continue;
      }
    }
    U.set(I.Trampoline);
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
  NF->setComdat(I.Original->getComdat());
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

static bool shouldRemove(const Instruction* I) {
  return I->use_empty() && isNoSanitize(I);
}

static void removeSanitizerInstructions(Function* F, const TargetTransformInfo& TTI) {
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

  // TODO(yln): this shouldn't be needed anymore, since we schedule a whole run of CFGSimplifyPass
  for (auto BBIt = F->begin(); BBIt != F->end(); ) {
    BasicBlock& BB = *(BBIt++); // Advance iterator since SimplifyCFG might delete the current BB
    simplifyCFG(&BB, TTI, BonusInstThreshold);
  }
}

void ControlFlowDiversity::removeSanitizerChecks(Function* F) {
//  auto& TTI = getAnalysis<TargetTransformInfoWrapperPass>().getTTI(*F);
  removeSanitizerAttributes(F);
  // removeSanitizerInstructions(F, TTI); // TODO(yln): Support UBSan
  // This is here for sanitizers (like UBSan) that insert instrumentation, before our CFD pass.
  // The current issue is that this also partly removes SanCov instrumentation, and
  // has some weird interaction when simplifying CFGs that had critical edges added by SanCov.
}

//  struct func_t {
//    uintptr_t* rand_loc;        // Randomized ptr location
//    const uintptr_t* variants;  // Variant pointers
//    uint32_t v_count;           // Number of variants
//  };
StructType* ControlFlowDiversity::createDescTy(Module& M) {
  auto& C = M.getContext();
  auto* Int32Ty = Type::getInt32Ty(C);
  auto* PtrPtrTy = getPtrTy(M)->getPointerTo();
  Type* Fields[] {PtrPtrTy, PtrPtrTy, Int32Ty};
  return StructType::create(C, Fields, "struct.cf_desc");
}

static Constant* createVariantPtrInit(ArrayRef<Function*> Variants, Type* PtrTy) {
  std::vector<Constant*> Elems;
  for (auto* F : Variants) {
    auto* FnPtr = ConstantExpr::getPtrToInt(F, PtrTy);
    Elems.push_back(FnPtr);
  }
  auto* Ty = ArrayType::get(PtrTy, Variants.size());
  return ConstantArray::get(Ty, Elems);
}

static GlobalVariable* createArray(Module& M, StringRef Name, Type* ElementTy, size_t Count, Constant* Init, Comdat* Comdat) {
  auto* Ty = ArrayType::get(ElementTy, Count);
  bool isConstant = true;
  auto Linkage = GlobalValue::PrivateLinkage;
  auto N = "__cf_gen_variants." + Name;
  auto* GV = new GlobalVariable(M, Ty, isConstant, Linkage, Init, N);
  GV->setComdat(Comdat);
  return GV;
}

static Constant* createDescInit(Module& M, StructType* DescTy, FInfo& I, GlobalVariable* Variants) {
  auto& C = M.getContext();
  auto* Int32Ty = Type::getInt32Ty(C);
  auto* Zero = ConstantInt::get(Int32Ty, 0);
  Constant* Indices[]{Zero, Zero};
  auto* VariantArrayPtr = ConstantExpr::getGetElementPtr(nullptr, Variants, Indices);
  auto* VariantCount = ConstantInt::get(Int32Ty, I.Variants.size());

  Constant* Fields[]{I.RandLoc, VariantArrayPtr, VariantCount};
  return ConstantStruct::get(DescTy, Fields);
}

static void emitDescription(Module& M, StringRef Name, StructType* DescTy, Constant* Init, Comdat* Comdat) {
  auto& DL = M.getDataLayout();
  auto isConstant = true;
  auto Linkage = GlobalValue::PrivateLinkage;
  auto N = "__cf_gen_desc." + Name;
  auto* GV = new GlobalVariable(M, DescTy, isConstant, Linkage, Init, N);
  GV->setComdat(Comdat);
  GV->setSection("__cf_gen_desc");
  GV->setAlignment(DL.getPointerSize());
}

void ControlFlowDiversity::emitMetadata(Module& M, FInfo &I, StructType* DescTy) {
  auto* PtrTy = getPtrTy(M);
  auto* Comdat = I.Original->getComdat();

  // Create variant array
  auto Count = I.Variants.size();
  auto* VariantInit = createVariantPtrInit(I.Variants, PtrTy);
  auto* Variants = createArray(M, I.Name, PtrTy, Count, VariantInit, Comdat);

  // Emit description
  auto* DescInit = createDescInit(M, DescTy, I, Variants);
  emitDescription(M, I.Name, DescTy, DescInit, Comdat);
}

static GlobalVariable* declareSectionGlobal(Module &M, StringRef Name, Type *Ty) {
  auto Linkage = GlobalValue::ExternalLinkage;
  auto* GV = new GlobalVariable(M, Ty, /* isConstant */ false,
                                Linkage, /* Initializer */ nullptr, Name);
  GV->setVisibility(GlobalValue::HiddenVisibility);
  return GV;
}

void ControlFlowDiversity::createModuleCtor(Module& M, StructType* DescTy) {
  auto* DescPtrTy = DescTy->getPointerTo();
  auto* Start = declareSectionGlobal(M, "__start___cf_gen_desc" , DescPtrTy);
  auto* End = declareSectionGlobal(M, "__stop___cf_gen_desc" , DescPtrTy);

  // void __cf_register(const func_t* start, const func_t* end)
  Type* ArgTys[]{DescPtrTy, DescPtrTy};
  Value* Args[] {
      ConstantExpr::getPointerCast(Start, DescPtrTy),
      ConstantExpr::getPointerCast(End, DescPtrTy)
  };

  Function* Ctor;
  std::tie(Ctor, std::ignore) = llvm::createSanitizerCtorAndInitFunctions(
      M, CtorName, "__cf_register", ArgTys, Args);
  Ctor->setComdat(M.getOrInsertComdat(CtorName)); // Deduplicate ctor
  appendToGlobalCtors(M, Ctor, /* Priority */ 0, Ctor);
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
        if (!var->getName().startswith("__cf_gen_randloc.")) continue;

        insertTraceFPrintf(M, "returned to "+ FName, "return_"+ FName, I.getNextNode());
      }
    }
  }
}
