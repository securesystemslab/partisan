// TODO: llvm file header

#include "FuzzerControlFlowRuntime.h"

#include "FuzzerDefs.h"

namespace fuzzer {

ControlFlowRuntime CFR;

void ControlFlowRuntime::ActivateFullSanitization() {
  assert(isActive());
  for (auto& F : Funcs)
    F.ActivateVariant(V_FullSanitization);
}

void ControlFlowRuntime::RestoreSanitizationLevels() {
  assert(isActive());
  for (auto& F : Funcs) {
    if (F.isFullyExplored())
      F.ActivateVariant(V_CoverageOnly);
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
    fuzzer::CFR.Register(F);
  }
}

} // extern "C"
