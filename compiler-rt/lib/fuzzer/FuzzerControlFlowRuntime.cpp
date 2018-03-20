// TODO: llvm file header

#include "FuzzerControlFlowRuntime.h"

#include "FuzzerDefs.h"
#include "FuzzerUtil.h"

namespace fuzzer {

void ControlFlowRuntime::registerFunc(Func& F) {
  Funcs.push_back(F);
  F.activateVariant(V_Coverage);
}

void ControlFlowRuntime::completeFuncRegistration() {
  assert(isActive());
  std::sort(Funcs.begin(), Funcs.end());
  assert(std::unique(Funcs.begin(), Funcs.end()) == Funcs.end());
  Printf("INFO: Registered %zu functions with CFD runtime\n", Funcs.size());
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
      I->activateVariant(V_Fast);
      Printf("\tCFD: Activated fast variant for ");
      PrintPC("%f %L\n", "%p\n", PC + 1);
    }
  }
}

void ControlFlowRuntime::activateFullSanitization() {
  assert(isActive());
  for (auto& F : Funcs) {
    F.activateVariant(V_Sanitization);
  }
}

void ControlFlowRuntime::restoreCoverageLevels() {
  assert(isActive());
  for (auto& F : Funcs) {
    auto V = F.isFullyExplored() ? V_Fast : V_Coverage;
    F.activateVariant(V);
  }
}

void ControlFlowRuntime::printStats() const {
  size_t Total = Funcs.size();
  size_t Unexplored = 0, PartiallyExplored = 0, FullyExplored = 0;
  for (auto& F : Funcs) {
    if (F.isUnexplored())         Unexplored++;
    else if (F.isFullyExplored()) FullyExplored++;
    else                          PartiallyExplored++;
  }
  assert (Unexplored + PartiallyExplored + FullyExplored == Total);
  Printf("CFD: %zd/%zd/%zd/%zd (un-/partially-/fully-explored/total) functions\n",
      Unexplored, PartiallyExplored, FullyExplored, Total);
}

// Forces initialization so we can access runtime instance from __cf_register,
// which runs very early, i.e., before C++ initializers.
static ControlFlowRuntime& getCFR() {
  static ControlFlowRuntime Instance;
  return Instance;
}

ControlFlowRuntime& CFR = getCFR();

} // namespace fuzzer

extern "C" {

ATTRIBUTE_INTERFACE
ATTRIBUTE_NO_SANITIZE_ALL
void __cf_register(const func_t* start, const func_t* end) {
  for (; start < end; start++) {
    const func_t& f = *start;
    fuzzer::ControlFlowRuntime::Func F(f.rand_loc, f.variants, f.v_count);
    fuzzer::getCFR().registerFunc(F);
  }
}

} // extern "C"
