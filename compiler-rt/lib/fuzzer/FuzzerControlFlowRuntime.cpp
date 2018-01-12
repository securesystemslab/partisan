// TODO: llvm file header

#include "FuzzerControlFlowRuntime.h"

#include "FuzzerDefs.h"
#include "FuzzerUtil.h"

namespace fuzzer {

ControlFlowRuntime CFR;

void ControlFlowRuntime::completeFuncRegistration() {
  assert(isActive());
  std::sort(Funcs.begin(), Funcs.end());
  assert(std::unique(Funcs.begin(), Funcs.end()) == Funcs.end());
}

void ControlFlowRuntime::registerPC(uintptr_t EntryBlock, uintptr_t LastBlock, uint32_t NumPCs) {
  assert(isActive());
  auto Key = Func::makeKey(EntryBlock);
  auto I = std::lower_bound(Funcs.begin(), Funcs.end(), Key);
  if (I != Funcs.end() && I->address() == EntryBlock)
    I->setPCData(LastBlock, NumPCs);
}

void ControlFlowRuntime::handleNewObservedPC(uintptr_t PC) {
  assert(isActive());
  auto Key = Func::makeKey(PC);
  auto I = std::upper_bound(Funcs.begin(), Funcs.end(), Key);
  if (I != Funcs.begin() && (--I)->lastAddress() >= PC) {
    assert(I->address() <= PC && PC <= I->lastAddress());
    if (I->handleNewObservedPC()) {
      auto VariantNo = V_CoverageOnly;
      I->activateVariant(VariantNo);
      Printf("\tCFD: Activated variant %u for ", VariantNo);
      PrintPC("%f %L\n", "%p\n", PC + 1);
    }
  }
}

void ControlFlowRuntime::activateFullSanitization() {
  assert(isActive());
  for (auto& F : Funcs) {
    F.activateVariant(V_FullSanitization);
  }
}

void ControlFlowRuntime::restoreSanitizationLevels() {
  assert(isActive());
  for (auto& F : Funcs) {
    if (F.isFullyExplored())
      F.activateVariant(V_CoverageOnly);
  }
}

} // namespace fuzzer

extern "C" {

ATTRIBUTE_INTERFACE
ATTRIBUTE_NO_SANITIZE_ALL
void __cf_register(const func_t* funcs, uintptr_t* rand_ptrs, uint32_t f_count) {
  for (uint32_t i = 0; i < f_count; i++) {
    const func_t& f = funcs[i];
    fuzzer::ControlFlowRuntime::Func F(f.variants, &rand_ptrs[i], f.v_count);
    fuzzer::CFR.registerFunc(F);
  }
}

} // extern "C"
