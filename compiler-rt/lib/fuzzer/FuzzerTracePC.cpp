//===- FuzzerTracePC.cpp - PC tracing--------------------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// Trace PCs.
// This module implements __sanitizer_cov_trace_pc_guard[_init],
// the callback required for -fsanitize-coverage=trace-pc-guard instrumentation.
//
//===----------------------------------------------------------------------===//

#include "FuzzerTracePC.h"
#include "FuzzerCorpus.h"
#include "FuzzerDefs.h"
#include "FuzzerDictionary.h"
#include "FuzzerExtFunctions.h"
#include "FuzzerIO.h"
#include "FuzzerUtil.h"
#include "FuzzerValueBitMap.h"
#include <set>

// The coverage counters and PCs.
// These are declared as global variables named "__sancov_*" to simplify
// experiments with inlined instrumentation.
alignas(64) ATTRIBUTE_INTERFACE
uint8_t __sancov_trace_pc_guard_8bit_counters[fuzzer::TracePC::kNumPCs];

ATTRIBUTE_INTERFACE
uintptr_t __sancov_trace_pc_pcs[fuzzer::TracePC::kNumPCs];

// Used by -fsanitize-coverage=stack-depth to track stack depth
ATTRIBUTE_INTERFACE __attribute__((tls_model("initial-exec")))
thread_local uintptr_t __sancov_lowest_stack;

namespace fuzzer {

TracePC TPC;

int ScopedDoingMyOwnMemOrStr::DoingMyOwnMemOrStr;

uint8_t *TracePC::Counters() const {
  return __sancov_trace_pc_guard_8bit_counters;
}

uintptr_t *TracePC::PCs() const {
  return __sancov_trace_pc_pcs;
}

size_t TracePC::GetTotalPCCoverage() {
  if (ObservedPCs.size())
    return ObservedPCs.size();
  size_t Res = 0;
  for (size_t i = 1, N = GetNumPCs(); i < N; i++)
    if (PCs()[i])
      Res++;
  return Res;
}


void TracePC::HandleInline8bitCountersInit(uint8_t *Start, uint8_t *Stop) {
  if (Start == Stop) return;
  if (NumModulesWithInline8bitCounters &&
      ModuleCounters[NumModulesWithInline8bitCounters-1].Start == Start) return;
  assert(NumModulesWithInline8bitCounters <
         sizeof(ModuleCounters) / sizeof(ModuleCounters[0]));
  ModuleCounters[NumModulesWithInline8bitCounters++] = {Start, Stop};
  NumInline8bitCounters += Stop - Start;
}

void TracePC::HandlePCsInit(const uintptr_t *Start, const uintptr_t *Stop) {
  const PCTableEntry *B = reinterpret_cast<const PCTableEntry *>(Start);
  const PCTableEntry *E = reinterpret_cast<const PCTableEntry *>(Stop);
  if (NumPCTables && ModulePCTable[NumPCTables - 1].Start == B) return;
  assert(NumPCTables < sizeof(ModulePCTable) / sizeof(ModulePCTable[0]));
  ModulePCTable[NumPCTables++] = {B, E};
  NumPCsInPCTables += E - B;
}

void TracePC::HandleInit(uint32_t *Start, uint32_t *Stop) {
  if (Start == Stop || *Start) return;
  assert(NumModules < sizeof(Modules) / sizeof(Modules[0]));
  for (uint32_t *P = Start; P < Stop; P++) {
    NumGuards++;
    if (NumGuards == kNumPCs) {
      RawPrint(
          "WARNING: The binary has too many instrumented PCs.\n"
          "         You may want to reduce the size of the binary\n"
          "         for more efficient fuzzing and precise coverage data\n");
    }
    *P = NumGuards % kNumPCs;
  }
  Modules[NumModules].Start = Start;
  Modules[NumModules].Stop = Stop;
  NumModules++;
}

void TracePC::PrintModuleInfo() {
  if (NumGuards) {
    Printf("INFO: Loaded %zd modules   (%zd guards): ", NumModules, NumGuards);
    for (size_t i = 0; i < NumModules; i++)
      Printf("%zd [%p, %p), ", Modules[i].Stop - Modules[i].Start,
             Modules[i].Start, Modules[i].Stop);
    Printf("\n");
  }
  if (NumModulesWithInline8bitCounters) {
    Printf("INFO: Loaded %zd modules   (%zd inline 8-bit counters): ",
           NumModulesWithInline8bitCounters, NumInline8bitCounters);
    for (size_t i = 0; i < NumModulesWithInline8bitCounters; i++)
      Printf("%zd [%p, %p), ", ModuleCounters[i].Stop - ModuleCounters[i].Start,
             ModuleCounters[i].Start, ModuleCounters[i].Stop);
    Printf("\n");
  }
  if (NumPCTables) {
    Printf("INFO: Loaded %zd PC tables (%zd PCs): ", NumPCTables,
           NumPCsInPCTables);
    for (size_t i = 0; i < NumPCTables; i++) {
      Printf("%zd [%p,%p), ", ModulePCTable[i].Stop - ModulePCTable[i].Start,
             ModulePCTable[i].Start, ModulePCTable[i].Stop);
    }
    Printf("\n");

    if ((NumGuards && NumGuards != NumPCsInPCTables) ||
        (NumInline8bitCounters && NumInline8bitCounters != NumPCsInPCTables)) {
      Printf("ERROR: The size of coverage PC tables does not match the\n"
             "number of instrumented PCs. This might be a compiler bug,\n"
             "please contact the libFuzzer developers.\n"
             "Also check https://bugs.llvm.org/show_bug.cgi?id=34636\n"
             "for possible workarounds (tl;dr: don't use the old GNU ld)\n");
      _Exit(1);
    }
  }
  if (size_t NumClangCounters = ClangCountersEnd() - ClangCountersBegin())
    Printf("INFO: %zd Clang Coverage Counters\n", NumClangCounters);
}

ATTRIBUTE_NO_SANITIZE_ALL
void TracePC::HandleCallerCallee(uintptr_t Caller, uintptr_t Callee) {
  const uintptr_t kBits = 12;
  const uintptr_t kMask = (1 << kBits) - 1;
  uintptr_t Idx = (Caller & kMask) | ((Callee & kMask) << kBits);
  ValueProfileMap.AddValueModPrime(Idx);
}

void TracePC::InitFunctionInfos() {
  for (size_t i = 0; i < NumPCTables; i++) {
    auto& M = ModulePCTable[i];
    for (auto* E = M.Start; E < M.Stop; E++) {
      if (E->PCFlags & 1) {// PC for function entry block
        FuncsByPC.emplace_back(FInfo{E->PC, 0});
//        Printf("\nfunction[%p]: ", E->PC);
      }

      FuncsByPC.back().NumUnobservedPCs++;
//      Printf(", %p", E->PC);
    }
  }
//  Printf("\n\n");
  std::sort(FuncsByPC.begin(), FuncsByPC.end());
}

// Defined in [ControlFlowRuntime.c]
extern "C" void __cf_activate_variant(uintptr_t func, uint32_t variant_no);
extern "C" void __cf_activate_variants(uint32_t variant_no);

constexpr uint32_t V_FullSanitization = 0;
constexpr uint32_t V_CoverageOnly = 1;
constexpr uint32_t V_Unsanitized = 2;

void TracePC::ActivateFullSanitization() {
  __cf_activate_variants(V_FullSanitization);
}

void TracePC::RestoreSanitizationLevels() {
  for (FInfo &I : FuncsByPC) {
    if (I.NumUnobservedPCs == 0) {
      __cf_activate_variant(I.EntryBlockPC, V_CoverageOnly);
    }
  }
}

void TracePC::HandleNewObservedPC(uintptr_t PC) {
  auto I = std::upper_bound(FuncsByPC.begin(), FuncsByPC.end(), FInfo{PC});
  assert(I != FuncsByPC.begin());
  --I;
//  Printf("New PC: %p, found function: %p\n", PC, I->EntryBlockPC);
  assert(I != FuncsByPC.end());
  assert(I->NumUnobservedPCs > 0); // We require that this function is only called once per PC
  I->NumUnobservedPCs--;
  if (I->NumUnobservedPCs == 0) {
    auto VariantNo = V_CoverageOnly;
    __cf_activate_variant(I->EntryBlockPC, VariantNo);
    Printf("\tCFD: Activated variant %u for ", VariantNo);
    PrintPC("%f %L\n", "%p\n", PC + 1);
  }
}

void TracePC::UpdateObservedPCs() {
  Vector<uintptr_t> CoveredFuncs;
  auto ObservePC = [&](uintptr_t PC) {
    if (ObservedPCs.insert(PC).second) {
      if (DoPrintNewPCs)
        PrintPC("\tNEW_PC: %p %F %L\n", "\tNEW_PC: %p\n", PC + 1);
      HandleNewObservedPC(PC);
    }
  };

  auto Observe = [&](const PCTableEntry &TE) {
    if (TE.PCFlags & 1)
      if (ObservedFuncs.insert(TE.PC).second && NumPrintNewFuncs)
        CoveredFuncs.push_back(TE.PC);
    ObservePC(TE.PC);
  };

  if (NumPCsInPCTables) {
    if (NumInline8bitCounters == NumPCsInPCTables) {
      for (size_t i = 0; i < NumModulesWithInline8bitCounters; i++) {
        uint8_t *Beg = ModuleCounters[i].Start;
        size_t Size = ModuleCounters[i].Stop - Beg;
        assert(Size ==
               (size_t)(ModulePCTable[i].Stop - ModulePCTable[i].Start));
        for (size_t j = 0; j < Size; j++)
          if (Beg[j])
            Observe(ModulePCTable[i].Start[j]);
      }
    } else if (NumGuards == NumPCsInPCTables) {
      size_t GuardIdx = 1;
      for (size_t i = 0; i < NumModules; i++) {
        uint32_t *Beg = Modules[i].Start;
        size_t Size = Modules[i].Stop - Beg;
        assert(Size ==
               (size_t)(ModulePCTable[i].Stop - ModulePCTable[i].Start));
        for (size_t j = 0; j < Size; j++, GuardIdx++)
          if (Counters()[GuardIdx])
            Observe(ModulePCTable[i].Start[j]);
      }
    }
  }
  if (size_t NumClangCounters =
      ClangCountersEnd() - ClangCountersBegin()) {
    auto P = ClangCountersBegin();
    for (size_t Idx = 0; Idx < NumClangCounters; Idx++)
      if (P[Idx])
        ObservePC((uintptr_t)Idx);
  }

  for (size_t i = 0, N = Min(CoveredFuncs.size(), NumPrintNewFuncs); i < N; i++) {
    Printf("\tNEW_FUNC[%zd/%zd]: ", i, CoveredFuncs.size());
    PrintPC("%p %F %L\n", "%p\n", CoveredFuncs[i] + 1);
  }
}

inline ALWAYS_INLINE uintptr_t GetPreviousInstructionPc(uintptr_t PC) {
  // TODO: this implementation is x86 only.
  // see sanitizer_common GetPreviousInstructionPc for full implementation.
  return PC - 1;
}

inline ALWAYS_INLINE uintptr_t GetNextInstructionPc(uintptr_t PC) {
  // TODO: this implementation is x86 only.
  // see sanitizer_common GetPreviousInstructionPc for full implementation.
  return PC + 1;
}

static std::string GetModuleName(uintptr_t PC) {
  char ModulePathRaw[4096] = "";  // What's PATH_MAX in portable C++?
  void *OffsetRaw = nullptr;
  if (!EF->__sanitizer_get_module_and_offset_for_pc(
      reinterpret_cast<void *>(PC), ModulePathRaw,
      sizeof(ModulePathRaw), &OffsetRaw))
    return "";
  return ModulePathRaw;
}

void TracePC::PrintCoverage() {
  if (!EF->__sanitizer_symbolize_pc ||
      !EF->__sanitizer_get_module_and_offset_for_pc) {
    Printf("INFO: __sanitizer_symbolize_pc or "
           "__sanitizer_get_module_and_offset_for_pc is not available,"
           " not printing coverage\n");
    return;
  }
  Printf("COVERAGE:\n");
  std::string LastFunctionName = "";
  std::string LastFileStr = "";
  Set<size_t> UncoveredLines;
  Set<size_t> CoveredLines;

  auto FunctionEndCallback = [&](const std::string &CurrentFunc,
                                 const std::string &CurrentFile) {
    if (LastFunctionName != CurrentFunc) {
      if (CoveredLines.empty() && !UncoveredLines.empty()) {
        Printf("UNCOVERED_FUNC: %s\n", LastFunctionName.c_str());
      } else {
        for (auto Line : UncoveredLines) {
          if (!CoveredLines.count(Line))
            Printf("UNCOVERED_LINE: %s %s:%zd\n", LastFunctionName.c_str(),
                   LastFileStr.c_str(), Line);
        }
      }

      UncoveredLines.clear();
      CoveredLines.clear();
      LastFunctionName = CurrentFunc;
      LastFileStr = CurrentFile;
    }
  };

  for (size_t i = 0; i < NumPCTables; i++) {
    auto &M = ModulePCTable[i];
    assert(M.Start < M.Stop);
    auto ModuleName = GetModuleName(M.Start->PC);
    for (auto Ptr = M.Start; Ptr < M.Stop; Ptr++) {
      auto PC = Ptr->PC;
      auto VisualizePC = GetNextInstructionPc(PC);
      bool IsObserved = ObservedPCs.count(PC);
      std::string FileStr = DescribePC("%s", VisualizePC);
      if (!IsInterestingCoverageFile(FileStr)) continue;
      std::string FunctionStr = DescribePC("%F", VisualizePC);
      FunctionEndCallback(FunctionStr, FileStr);
      std::string LineStr = DescribePC("%l", VisualizePC);
      size_t Line = std::stoul(LineStr);
      if (IsObserved && CoveredLines.insert(Line).second)
        Printf("COVERED: %s %s:%zd\n", FunctionStr.c_str(), FileStr.c_str(),
               Line);
      else
        UncoveredLines.insert(Line);
    }
  }
  FunctionEndCallback("", "");
}

void TracePC::DumpCoverage() {
  if (EF->__sanitizer_dump_coverage) {
    Vector<uintptr_t> PCsCopy(GetNumPCs());
    for (size_t i = 0; i < GetNumPCs(); i++)
      PCsCopy[i] = PCs()[i] ? GetPreviousInstructionPc(PCs()[i]) : 0;
    EF->__sanitizer_dump_coverage(PCsCopy.data(), PCsCopy.size());
  }
}

// Value profile.
// We keep track of various values that affect control flow.
// These values are inserted into a bit-set-based hash map.
// Every new bit in the map is treated as a new coverage.
//
// For memcmp/strcmp/etc the interesting value is the length of the common
// prefix of the parameters.
// For cmp instructions the interesting value is a XOR of the parameters.
// The interesting value is mixed up with the PC and is then added to the map.

ATTRIBUTE_NO_SANITIZE_ALL
void TracePC::AddValueForMemcmp(void *caller_pc, const void *s1, const void *s2,
                                size_t n, bool StopAtZero) {
  if (!n) return;
  size_t Len = std::min(n, Word::GetMaxSize());
  const uint8_t *A1 = reinterpret_cast<const uint8_t *>(s1);
  const uint8_t *A2 = reinterpret_cast<const uint8_t *>(s2);
  uint8_t B1[Word::kMaxSize];
  uint8_t B2[Word::kMaxSize];
  // Copy the data into locals in this non-msan-instrumented function
  // to avoid msan complaining further.
  size_t Hash = 0;  // Compute some simple hash of both strings.
  for (size_t i = 0; i < Len; i++) {
    B1[i] = A1[i];
    B2[i] = A2[i];
    size_t T = B1[i];
    Hash ^= (T << 8) | B2[i];
  }
  size_t I = 0;
  for (; I < Len; I++)
    if (B1[I] != B2[I] || (StopAtZero && B1[I] == 0))
      break;
  size_t PC = reinterpret_cast<size_t>(caller_pc);
  size_t Idx = (PC & 4095) | (I << 12);
  ValueProfileMap.AddValue(Idx);
  TORCW.Insert(Idx ^ Hash, Word(B1, Len), Word(B2, Len));
}

template <class T>
ATTRIBUTE_TARGET_POPCNT ALWAYS_INLINE
ATTRIBUTE_NO_SANITIZE_ALL
void TracePC::HandleCmp(uintptr_t PC, T Arg1, T Arg2) {
  uint64_t ArgXor = Arg1 ^ Arg2;
  uint64_t ArgDistance = __builtin_popcountll(ArgXor) + 1; // [1,65]
  uintptr_t Idx = ((PC & 4095) + 1) * ArgDistance;
  if (sizeof(T) == 4)
      TORC4.Insert(ArgXor, Arg1, Arg2);
  else if (sizeof(T) == 8)
      TORC8.Insert(ArgXor, Arg1, Arg2);
  ValueProfileMap.AddValue(Idx);
}

static size_t InternalStrnlen(const char *S, size_t MaxLen) {
  size_t Len = 0;
  for (; Len < MaxLen && S[Len]; Len++) {}
  return Len;
}

// Finds min of (strlen(S1), strlen(S2)).
// Needed bacause one of these strings may actually be non-zero terminated.
static size_t InternalStrnlen2(const char *S1, const char *S2) {
  size_t Len = 0;
  for (; S1[Len] && S2[Len]; Len++)  {}
  return Len;
}

void TracePC::ClearInlineCounters() {
  for (size_t i = 0; i < NumModulesWithInline8bitCounters; i++) {
    uint8_t *Beg = ModuleCounters[i].Start;
    size_t Size = ModuleCounters[i].Stop - Beg;
    memset(Beg, 0, Size);
  }
}

ATTRIBUTE_NO_SANITIZE_ALL
void TracePC::RecordInitialStack() {
  int stack;
  __sancov_lowest_stack = InitialStack = reinterpret_cast<uintptr_t>(&stack);
}

uintptr_t TracePC::GetMaxStackOffset() const {
  return InitialStack - __sancov_lowest_stack;  // Stack grows down
}

} // namespace fuzzer

extern "C" {
ATTRIBUTE_INTERFACE
ATTRIBUTE_NO_SANITIZE_ALL
void __sanitizer_cov_trace_pc_guard(uint32_t *Guard) {
  uintptr_t PC = reinterpret_cast<uintptr_t>(__builtin_return_address(0));
  uint32_t Idx = *Guard;
  __sancov_trace_pc_pcs[Idx] = PC;
  __sancov_trace_pc_guard_8bit_counters[Idx]++;
}

// Best-effort support for -fsanitize-coverage=trace-pc, which is available
// in both Clang and GCC.
ATTRIBUTE_INTERFACE
ATTRIBUTE_NO_SANITIZE_ALL
void __sanitizer_cov_trace_pc() {
  uintptr_t PC = reinterpret_cast<uintptr_t>(__builtin_return_address(0));
  uintptr_t Idx = PC & (((uintptr_t)1 << fuzzer::TracePC::kTracePcBits) - 1);
  __sancov_trace_pc_pcs[Idx] = PC;
  __sancov_trace_pc_guard_8bit_counters[Idx]++;
}

ATTRIBUTE_INTERFACE
void __sanitizer_cov_trace_pc_guard_init(uint32_t *Start, uint32_t *Stop) {
  fuzzer::TPC.HandleInit(Start, Stop);
}

ATTRIBUTE_INTERFACE
void __sanitizer_cov_8bit_counters_init(uint8_t *Start, uint8_t *Stop) {
  fuzzer::TPC.HandleInline8bitCountersInit(Start, Stop);
}

ATTRIBUTE_INTERFACE
void __sanitizer_cov_pcs_init(const uintptr_t *pcs_beg,
                              const uintptr_t *pcs_end) {
  fuzzer::TPC.HandlePCsInit(pcs_beg, pcs_end);
}

ATTRIBUTE_INTERFACE
ATTRIBUTE_NO_SANITIZE_ALL
void __sanitizer_cov_trace_pc_indir(uintptr_t Callee) {
  uintptr_t PC = reinterpret_cast<uintptr_t>(__builtin_return_address(0));
  fuzzer::TPC.HandleCallerCallee(PC, Callee);
}

ATTRIBUTE_INTERFACE
ATTRIBUTE_NO_SANITIZE_ALL
ATTRIBUTE_TARGET_POPCNT
void __sanitizer_cov_trace_cmp8(uint64_t Arg1, uint64_t Arg2) {
  uintptr_t PC = reinterpret_cast<uintptr_t>(__builtin_return_address(0));
  fuzzer::TPC.HandleCmp(PC, Arg1, Arg2);
}

ATTRIBUTE_INTERFACE
ATTRIBUTE_NO_SANITIZE_ALL
ATTRIBUTE_TARGET_POPCNT
// Now the __sanitizer_cov_trace_const_cmp[1248] callbacks just mimic
// the behaviour of __sanitizer_cov_trace_cmp[1248] ones. This, however,
// should be changed later to make full use of instrumentation.
void __sanitizer_cov_trace_const_cmp8(uint64_t Arg1, uint64_t Arg2) {
  uintptr_t PC = reinterpret_cast<uintptr_t>(__builtin_return_address(0));
  fuzzer::TPC.HandleCmp(PC, Arg1, Arg2);
}

ATTRIBUTE_INTERFACE
ATTRIBUTE_NO_SANITIZE_ALL
ATTRIBUTE_TARGET_POPCNT
void __sanitizer_cov_trace_cmp4(uint32_t Arg1, uint32_t Arg2) {
  uintptr_t PC = reinterpret_cast<uintptr_t>(__builtin_return_address(0));
  fuzzer::TPC.HandleCmp(PC, Arg1, Arg2);
}

ATTRIBUTE_INTERFACE
ATTRIBUTE_NO_SANITIZE_ALL
ATTRIBUTE_TARGET_POPCNT
void __sanitizer_cov_trace_const_cmp4(uint32_t Arg1, uint32_t Arg2) {
  uintptr_t PC = reinterpret_cast<uintptr_t>(__builtin_return_address(0));
  fuzzer::TPC.HandleCmp(PC, Arg1, Arg2);
}

ATTRIBUTE_INTERFACE
ATTRIBUTE_NO_SANITIZE_ALL
ATTRIBUTE_TARGET_POPCNT
void __sanitizer_cov_trace_cmp2(uint16_t Arg1, uint16_t Arg2) {
  uintptr_t PC = reinterpret_cast<uintptr_t>(__builtin_return_address(0));
  fuzzer::TPC.HandleCmp(PC, Arg1, Arg2);
}

ATTRIBUTE_INTERFACE
ATTRIBUTE_NO_SANITIZE_ALL
ATTRIBUTE_TARGET_POPCNT
void __sanitizer_cov_trace_const_cmp2(uint16_t Arg1, uint16_t Arg2) {
  uintptr_t PC = reinterpret_cast<uintptr_t>(__builtin_return_address(0));
  fuzzer::TPC.HandleCmp(PC, Arg1, Arg2);
}

ATTRIBUTE_INTERFACE
ATTRIBUTE_NO_SANITIZE_ALL
ATTRIBUTE_TARGET_POPCNT
void __sanitizer_cov_trace_cmp1(uint8_t Arg1, uint8_t Arg2) {
  uintptr_t PC = reinterpret_cast<uintptr_t>(__builtin_return_address(0));
  fuzzer::TPC.HandleCmp(PC, Arg1, Arg2);
}

ATTRIBUTE_INTERFACE
ATTRIBUTE_NO_SANITIZE_ALL
ATTRIBUTE_TARGET_POPCNT
void __sanitizer_cov_trace_const_cmp1(uint8_t Arg1, uint8_t Arg2) {
  uintptr_t PC = reinterpret_cast<uintptr_t>(__builtin_return_address(0));
  fuzzer::TPC.HandleCmp(PC, Arg1, Arg2);
}

ATTRIBUTE_INTERFACE
ATTRIBUTE_NO_SANITIZE_ALL
ATTRIBUTE_TARGET_POPCNT
void __sanitizer_cov_trace_switch(uint64_t Val, uint64_t *Cases) {
  uint64_t N = Cases[0];
  uint64_t ValSizeInBits = Cases[1];
  uint64_t *Vals = Cases + 2;
  // Skip the most common and the most boring case.
  if (Vals[N - 1]  < 256 && Val < 256)
    return;
  uintptr_t PC = reinterpret_cast<uintptr_t>(__builtin_return_address(0));
  size_t i;
  uint64_t Token = 0;
  for (i = 0; i < N; i++) {
    Token = Val ^ Vals[i];
    if (Val < Vals[i])
      break;
  }

  if (ValSizeInBits == 16)
    fuzzer::TPC.HandleCmp(PC + i, static_cast<uint16_t>(Token), (uint16_t)(0));
  else if (ValSizeInBits == 32)
    fuzzer::TPC.HandleCmp(PC + i, static_cast<uint32_t>(Token), (uint32_t)(0));
  else
    fuzzer::TPC.HandleCmp(PC + i, Token, (uint64_t)(0));
}

ATTRIBUTE_INTERFACE
ATTRIBUTE_NO_SANITIZE_ALL
ATTRIBUTE_TARGET_POPCNT
void __sanitizer_cov_trace_div4(uint32_t Val) {
  uintptr_t PC = reinterpret_cast<uintptr_t>(__builtin_return_address(0));
  fuzzer::TPC.HandleCmp(PC, Val, (uint32_t)0);
}

ATTRIBUTE_INTERFACE
ATTRIBUTE_NO_SANITIZE_ALL
ATTRIBUTE_TARGET_POPCNT
void __sanitizer_cov_trace_div8(uint64_t Val) {
  uintptr_t PC = reinterpret_cast<uintptr_t>(__builtin_return_address(0));
  fuzzer::TPC.HandleCmp(PC, Val, (uint64_t)0);
}

ATTRIBUTE_INTERFACE
ATTRIBUTE_NO_SANITIZE_ALL
ATTRIBUTE_TARGET_POPCNT
void __sanitizer_cov_trace_gep(uintptr_t Idx) {
  uintptr_t PC = reinterpret_cast<uintptr_t>(__builtin_return_address(0));
  fuzzer::TPC.HandleCmp(PC, Idx, (uintptr_t)0);
}

ATTRIBUTE_INTERFACE ATTRIBUTE_NO_SANITIZE_MEMORY
void __sanitizer_weak_hook_memcmp(void *caller_pc, const void *s1,
                                  const void *s2, size_t n, int result) {
  if (fuzzer::ScopedDoingMyOwnMemOrStr::DoingMyOwnMemOrStr) return;
  if (result == 0) return;  // No reason to mutate.
  if (n <= 1) return;  // Not interesting.
  fuzzer::TPC.AddValueForMemcmp(caller_pc, s1, s2, n, /*StopAtZero*/false);
}

ATTRIBUTE_INTERFACE ATTRIBUTE_NO_SANITIZE_MEMORY
void __sanitizer_weak_hook_strncmp(void *caller_pc, const char *s1,
                                   const char *s2, size_t n, int result) {
  if (fuzzer::ScopedDoingMyOwnMemOrStr::DoingMyOwnMemOrStr) return;
  if (result == 0) return;  // No reason to mutate.
  size_t Len1 = fuzzer::InternalStrnlen(s1, n);
  size_t Len2 = fuzzer::InternalStrnlen(s2, n);
  n = std::min(n, Len1);
  n = std::min(n, Len2);
  if (n <= 1) return;  // Not interesting.
  fuzzer::TPC.AddValueForMemcmp(caller_pc, s1, s2, n, /*StopAtZero*/true);
}

ATTRIBUTE_INTERFACE ATTRIBUTE_NO_SANITIZE_MEMORY
void __sanitizer_weak_hook_strcmp(void *caller_pc, const char *s1,
                                   const char *s2, int result) {
  if (fuzzer::ScopedDoingMyOwnMemOrStr::DoingMyOwnMemOrStr) return;
  if (result == 0) return;  // No reason to mutate.
  size_t N = fuzzer::InternalStrnlen2(s1, s2);
  if (N <= 1) return;  // Not interesting.
  fuzzer::TPC.AddValueForMemcmp(caller_pc, s1, s2, N, /*StopAtZero*/true);
}

ATTRIBUTE_INTERFACE ATTRIBUTE_NO_SANITIZE_MEMORY
void __sanitizer_weak_hook_strncasecmp(void *called_pc, const char *s1,
                                       const char *s2, size_t n, int result) {
  if (fuzzer::ScopedDoingMyOwnMemOrStr::DoingMyOwnMemOrStr) return;
  return __sanitizer_weak_hook_strncmp(called_pc, s1, s2, n, result);
}

ATTRIBUTE_INTERFACE ATTRIBUTE_NO_SANITIZE_MEMORY
void __sanitizer_weak_hook_strcasecmp(void *called_pc, const char *s1,
                                      const char *s2, int result) {
  if (fuzzer::ScopedDoingMyOwnMemOrStr::DoingMyOwnMemOrStr) return;
  return __sanitizer_weak_hook_strcmp(called_pc, s1, s2, result);
}

ATTRIBUTE_INTERFACE ATTRIBUTE_NO_SANITIZE_MEMORY
void __sanitizer_weak_hook_strstr(void *called_pc, const char *s1,
                                  const char *s2, char *result) {
  if (fuzzer::ScopedDoingMyOwnMemOrStr::DoingMyOwnMemOrStr) return;
  fuzzer::TPC.MMT.Add(reinterpret_cast<const uint8_t *>(s2), strlen(s2));
}

ATTRIBUTE_INTERFACE ATTRIBUTE_NO_SANITIZE_MEMORY
void __sanitizer_weak_hook_strcasestr(void *called_pc, const char *s1,
                                      const char *s2, char *result) {
  if (fuzzer::ScopedDoingMyOwnMemOrStr::DoingMyOwnMemOrStr) return;
  fuzzer::TPC.MMT.Add(reinterpret_cast<const uint8_t *>(s2), strlen(s2));
}

ATTRIBUTE_INTERFACE ATTRIBUTE_NO_SANITIZE_MEMORY
void __sanitizer_weak_hook_memmem(void *called_pc, const void *s1, size_t len1,
                                  const void *s2, size_t len2, void *result) {
  if (fuzzer::ScopedDoingMyOwnMemOrStr::DoingMyOwnMemOrStr) return;
  fuzzer::TPC.MMT.Add(reinterpret_cast<const uint8_t *>(s2), len2);
}
}  // extern "C"
