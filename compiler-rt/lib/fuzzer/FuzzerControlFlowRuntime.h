// TODO: llvm file header

#ifndef LLVM_FUZZER_CONTROLFLOWRUNTIME_H
#define LLVM_FUZZER_CONTROLFLOWRUNTIME_H

#include <cassert>
#include <cstdint>
#include <vector>

namespace {

struct func_t {
  const uintptr_t* variants;  // Variant pointers
  uint32_t v_count;           // Number of variants
};

} // anonymous namespace

namespace fuzzer {

class ControlFlowRuntime {
public:
  class Func {
    const uintptr_t* const Variants;
    uintptr_t* const RandLoc;
    const uint32_t VariantCount;
    uint32_t NumUnobservedPCs;

  public:
    Func(const uintptr_t *Variants, uintptr_t *RandLoc, uint32_t VariantCount)
        : Variants(Variants), RandLoc(RandLoc), VariantCount(VariantCount),
          NumUnobservedPCs(0) {}

    bool isFullyExplored() const { return NumUnobservedPCs == 0; }
    void ActivateVariant(uint32_t V) { *RandLoc = Variants[V]; }
  };

private:
  static constexpr uint32_t V_FullSanitization = 0;
  static constexpr uint32_t V_CoverageOnly = 1;
  static constexpr uint32_t V_Unsanitized = 2;

  std::vector<Func> Funcs;

public:
  bool isActive() const { return !Funcs.empty(); }
  void Register(const Func& F) { Funcs.push_back(F); }

  void ActivateFullSanitization();
  void RestoreSanitizationLevels();
};

extern ControlFlowRuntime CFR;

} // namespace fuzzer

#endif //LLVM_FUZZER_CONTROLFLOWRUNTIME_H
