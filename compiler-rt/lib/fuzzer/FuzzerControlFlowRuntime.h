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
    const uintptr_t* Variants;
    uintptr_t* RandLoc;
    uint32_t NumVariants;
    uintptr_t LastAddress{};
    uint32_t NumPCs{};
    uint32_t NumUnobservedPCs{};

  public:
    static Func makeKey(uintptr_t Address) {
      static uintptr_t Variants[1];
      Variants[0] = Address;
      return {Variants, nullptr, 0};
    }

    Func(const uintptr_t *Variants, uintptr_t *RandLoc, uint32_t NumVariants)
        : Variants(Variants), RandLoc(RandLoc), NumVariants(NumVariants) {}

    bool operator<(const Func& F) const { return address() < F.address(); }
    bool operator==(const Func& F) const { return address() == F.address(); }

    uintptr_t address() const { return Variants[0]; }
    uintptr_t lastAddress() const { return LastAddress; }

    void setPCData(uintptr_t LastAddr, uint32_t NumPCs) {
      LastAddress = LastAddr;
      this->NumPCs = NumPCs;
      NumUnobservedPCs = NumPCs;
    }

    bool isUnexplored() const { return NumPCs == NumUnobservedPCs; }
    bool isFullyExplored() const { return NumUnobservedPCs == 0; }
    bool handleNewObservedPC() { return --NumUnobservedPCs == 0; }
    void activateVariant(uint32_t V) { *RandLoc = Variants[V]; }
  };

private:
  static constexpr uint32_t V_FullSanitization = 0;
  static constexpr uint32_t V_CoverageOnly = 1;
  static constexpr uint32_t V_Unsanitized = 2;

  std::vector<Func> Funcs;

public:
  bool isActive() const { return !Funcs.empty(); }
  void registerFunc(Func& F);
  void completeFuncRegistration();
  void registerPC(uintptr_t EntryBlock, uintptr_t LastBlock, uint32_t NumPCs);
  void handleNewObservedPC(uintptr_t PC);
  void activateFullSanitization();
  void restoreSanitizationLevels();
  void printStats() const;
};

extern ControlFlowRuntime& CFR;

} // namespace fuzzer

#endif //LLVM_FUZZER_CONTROLFLOWRUNTIME_H
