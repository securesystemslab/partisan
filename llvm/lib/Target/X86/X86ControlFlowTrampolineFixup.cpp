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

static MachineOperand& getRandLocGlobal(MachineBasicBlock& MBB) {
  for (auto& I : MBB) {
    for (auto& Op : I.operands()) {
      if (Op.isGlobal() && Op.getGlobal()->getName().startswith("__cf_gen_randloc."))
        return Op;
    }
  }
  llvm_unreachable("trampoline must contain reference to randomized pointer location");
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

  // <more instructions>
  // %rax = MOV64rm %rip, 1, %noreg, @__cf_gen_randloc.foo, %noreg
  // TAILJMPr64 killed %rax
  // -->
  // TAILJMPm64 %rip, 1, %noreg, @__cf_gen_randloc.foo, %noreg

  auto* TTI = MF.getSubtarget().getInstrInfo();
  MachineInstr* Jmp = BuildMI(&MBB, DebugLoc(), TTI->get(X86::TAILJMPm64))
        .addReg(X86::RIP)
        .addImm(1)
        .addReg(0)
        .add(getRandLocGlobal(MBB))
        .addReg(0)
        ->removeFromParent();

  MBB.clear();
  MBB.push_back(Jmp);

  return true;
}
