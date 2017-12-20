//===- X86ControlFlowTrampolineFixup.cpp - Fixup control-flow trampolines -===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This machine function pass fixes up and optimizes control-flow diversity
// trampolines marked with a 'cf-trampoline' function attribute.
//
//===----------------------------------------------------------------------===//

#include "X86.h"
#include "X86InstrInfo.h"
#include "X86Subtarget.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"

using namespace llvm;

#define DEBUG_TYPE "control-flow-diversity"

namespace {

class ControlFlowTrampolineFixup : public MachineFunctionPass {
public:
  static char ID;
  ControlFlowTrampolineFixup() : MachineFunctionPass(ID) {}

  bool runOnMachineFunction(MachineFunction& MF) override;
};
} // namespace

char ControlFlowTrampolineFixup::ID = 0;

FunctionPass* llvm::createX86ControlFlowTrampolineFixupPass() {
  return new ControlFlowTrampolineFixup();
}

static MachineOperand& getRandPtrGlobal(MachineBasicBlock& MBB) {
  for (auto& I : MBB) {
    for (auto& OP : I.operands()) {
      if (OP.isGlobal() && OP.getGlobal()->getName() == "cf_rand_ptrs")
        return OP;
    }
  }
  llvm_unreachable("trampoline must contain reference to randomized pointer array");
}

bool ControlFlowTrampolineFixup::runOnMachineFunction(MachineFunction& MF) {
  if (!MF.getFunction().hasFnAttribute("cf-trampoline"))
    return false;

  assert (MF.size() == 1 && "trampoline must not have control flow");
  auto& MBB = MF.front();

  if (MBB.size() == 1) {
    assert (MBB.front().getOpcode() == X86::TAILJMPm64);
    return false;
  }

  // %RCX<def> = MOV64rm %RIP, 1, %noreg, <ga:@cf_rand_ptrs+8>, %noreg
  // <more instructions>
  // TAILJMPr64 %RCX<kill>
  // -->
  // TAILJMPm64 %RIP, 1, %noreg, <ga:@cf_rand_ptrs+8>, %noreg

  auto* TTI = MF.getSubtarget().getInstrInfo();
  MachineInstr* jmp = BuildMI(&MBB, DebugLoc(), TTI->get(X86::TAILJMPm64))
        .addReg(X86::RIP)
        .addImm(1)
        .addReg(0)
        .add(getRandPtrGlobal(MBB))
        .addReg(0)
        ->removeFromParent();

  MBB.clear();
  MBB.push_back(jmp);

  return true;
}
