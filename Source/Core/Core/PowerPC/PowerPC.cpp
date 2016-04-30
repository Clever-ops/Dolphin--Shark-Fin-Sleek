// Copyright 2008 Dolphin Emulator Project
// Licensed under GPLv2+
// Refer to the license.txt file included.

#include <condition_variable>
#include <mutex>

#include "Common/Assert.h"
#include "Common/ChunkFile.h"
#include "Common/CommonTypes.h"
#include "Common/FPURoundMode.h"
#include "Common/MathUtil.h"
#include "Common/Logging/Log.h"

#include "Core/ConfigManager.h"
#include "Core/Host.h"
#include "Core/HW/Memmap.h"
#include "Core/HW/SystemTimers.h"
#include "Core/PowerPC/CPUCoreBase.h"
#include "Core/PowerPC/JitInterface.h"
#include "Core/PowerPC/PowerPC.h"
#include "Core/PowerPC/PPCTables.h"
#include "Core/PowerPC/Interpreter/Interpreter.h"


CPUCoreBase *cpu_core_base;

namespace PowerPC
{

// STATE_TO_SAVE
PowerPCState ppcState;

static volatile CPUState s_state = CPU_POWERDOWN;

Interpreter* const  s_interpreter = Interpreter::getInstance();
static CoreMode     s_mode        = MODE_INTERPRETER;

static std::mutex s_state_change_lock;
static std::condition_variable s_state_change_cvar;
static unsigned int s_state_run_loop_enter_counter = 0;
static unsigned int s_state_run_loop_leave_counter = 0;

Watches watches;
BreakPoints breakpoints;
MemChecks memchecks;
PPCDebugInterface debug_interface;

u32 CompactCR()
{
	u32 new_cr = 0;
	for (int i = 0; i < 8; i++)
	{
		new_cr |= GetCRField(i) << (28 - i * 4);
	}
	return new_cr;
}

void ExpandCR(u32 cr)
{
	for (int i = 0; i < 8; i++)
	{
		SetCRField(i, (cr >> (28 - i * 4)) & 0xF);
	}
}

void DoState(PointerWrap &p)
{
	// some of this code has been disabled, because
	// it changes registers even in MODE_MEASURE (which is suspicious and seems like it could cause desyncs)
	// and because the values it's changing have been added to CoreTiming::DoState, so it might conflict to mess with them here.

	// rSPR(SPR_DEC) = SystemTimers::GetFakeDecrementer();
	// *((u64 *)&TL) = SystemTimers::GetFakeTimeBase(); //works since we are little endian and TL comes first :)

	p.DoPOD(ppcState);

	// SystemTimers::DecrementerSet();
	// SystemTimers::TimeBaseSet();

	JitInterface::DoState(p);
}

static void ResetRegisters()
{
	memset(ppcState.ps, 0, sizeof(ppcState.ps));
	memset(ppcState.gpr, 0, sizeof(ppcState.gpr));
	memset(ppcState.spr, 0, sizeof(ppcState.spr));
	/*
	0x00080200 = lonestar 2.0
	0x00088202 = lonestar 2.2
	0x70000100 = gekko 1.0
	0x00080100 = gekko 2.0
	0x00083203 = gekko 2.3a
	0x00083213 = gekko 2.3b
	0x00083204 = gekko 2.4
	0x00083214 = gekko 2.4e (8SE) - retail HW2
	*/
	ppcState.spr[SPR_PVR] = 0x00083214;
	ppcState.spr[SPR_HID1] = 0x80000000; // We're running at 3x the bus clock
	ppcState.spr[SPR_ECID_U] = 0x0d96e200;
	ppcState.spr[SPR_ECID_M] = 0x1840c00d;
	ppcState.spr[SPR_ECID_L] = 0x82bb08e8;

	ppcState.fpscr = 0;
	ppcState.pc = 0;
	ppcState.npc = 0;
	ppcState.Exceptions = 0;
	for (auto& v : ppcState.cr_val)
		v = 0x8000000000000001;

	TL = 0;
	TU = 0;
	SystemTimers::TimeBaseSet();

	// MSR should be 0x40, but we don't emulate BS1, so it would never be turned off :}
	ppcState.msr = 0;
	rDEC = 0xFFFFFFFF;
	SystemTimers::DecrementerSet();
}

void Init(int cpu_core)
{
	// NOTE: This function runs on EmuThread, not the CPU Thread.
	//   Changing the rounding mode has a limited effect.
	FPURoundMode::SetPrecisionMode(FPURoundMode::PREC_53);

	memset(ppcState.sr, 0, sizeof(ppcState.sr));
	ppcState.pagetable_base = 0;
	ppcState.pagetable_hashmask = 0;

	for (int tlb = 0; tlb < 2; tlb++)
	{
		for (int set = 0; set < 64; set++)
		{
			ppcState.tlb[tlb][set].recent = 0;
			for (int way = 0; way < 2; way++)
			{
				ppcState.tlb[tlb][set].paddr[way] = 0;
				ppcState.tlb[tlb][set].pte[way] = 0;
				ppcState.tlb[tlb][set].tag[way] = TLB_TAG_INVALID;
			}
		}
	}

	ResetRegisters();
	PPCTables::InitTables(cpu_core);

	// We initialize the interpreter because
	// it is used on boot and code window independently.
	s_interpreter->Init();

	switch (cpu_core)
	{
	case PowerPC::CORE_INTERPRETER:
		cpu_core_base = s_interpreter;
		break;

	default:
		cpu_core_base = JitInterface::InitJitCore(cpu_core);
		if (!cpu_core_base) // Handle Situations where JIT core isn't available
		{
			WARN_LOG(POWERPC, "Jit core %d not available. Defaulting to interpreter.", cpu_core);
			cpu_core_base = s_interpreter;
		}
		break;
	}

	if (cpu_core_base != s_interpreter)
	{
		s_mode = MODE_JIT;
	}
	else
	{
		s_mode = MODE_INTERPRETER;
	}
	s_state = CPU_STEPPING;

	ppcState.iCache.Init();

	if (SConfig::GetInstance().bEnableDebugging)
		breakpoints.ClearAllTemporary();
}

void Shutdown()
{
	JitInterface::Shutdown();
	s_interpreter->Shutdown();
	cpu_core_base = nullptr;
	s_state = CPU_POWERDOWN;
}

CoreMode GetMode()
{
	return s_mode;
}

void SetMode(CoreMode new_mode)
{
	if (new_mode == s_mode)
		return;  // We don't need to do anything.

	s_mode = new_mode;

	switch (s_mode)
	{
	case MODE_INTERPRETER:  // Switching from JIT to interpreter
		cpu_core_base = s_interpreter;
		break;

	case MODE_JIT:  // Switching from interpreter to JIT.
		// Don't really need to do much. It'll work, the cache will refill itself.
		cpu_core_base = JitInterface::GetCore();
		if (!cpu_core_base) // Has a chance to not get a working JIT core if one isn't active on host
			cpu_core_base = s_interpreter;
		break;
	}
}

void SingleStep()
{
	cpu_core_base->SingleStep();
}

void RunLoop()
{
	Host_UpdateDisasmDialog();
	{
		std::lock_guard<std::mutex> guard(s_state_change_lock);
		if (s_state != CPU_RUNNING)
			return;
		_assert_msg_(POWERPC, s_state_run_loop_enter_counter == s_state_run_loop_leave_counter, "Multiple RunLoop instances?");
		s_state_run_loop_enter_counter += 1;
	}
	cpu_core_base->Run();
	{
		std::lock_guard<std::mutex> guard(s_state_change_lock);
		s_state_run_loop_leave_counter += 1;
		s_state_change_cvar.notify_all();
	}
	Host_UpdateDisasmDialog();
}

CPUState GetState()
{
	return s_state;
}

const volatile CPUState *GetStatePtr()
{
	return &s_state;
}

void Start()
{
	std::lock_guard<std::mutex> guard(s_state_change_lock);
	CPUState old_state = s_state;
	s_state = CPU_RUNNING;

	// If the state is switched back to CPU_RUNNING before the CPU_STEPPING
	// or CPU_POWERDOWN has actually been processed then kick waiters.
	// NOTE: Calling PowerPC::Start before RunLoop ends is probably a race
	//   in the code that called us.
	if (old_state != CPU_RUNNING && s_state_run_loop_enter_counter != s_state_run_loop_leave_counter)
	{
		ERROR_LOG(POWERPC, "Possible race occurred. CPU is starting again before it stopped.");
		s_state_run_loop_leave_counter += 1;
		s_state_run_loop_enter_counter += 1;
		s_state_change_cvar.notify_all();
	}
}

static void ChangeStateFromRunning(CPUState new_state, bool synchronize)
{
	// WARNING: There's a difference between "old state" and "effective state".
	//   Just because the old state was already CPU_STEPPING doesn't mean that
	//   RunLoop has exited yet.
	std::unique_lock<std::mutex> guard(s_state_change_lock);
	// CPU_POWERDOWN is a latching state. Once set it can only be cleared by
	// PowerPC::Start or a Shutdown/Init cycle.
	if (s_state != CPU_POWERDOWN)
		s_state = new_state;

	// Wait for the CPU core to leave
	if (synchronize && s_state_run_loop_enter_counter != s_state_run_loop_leave_counter)
	{
		// If we are bringing the CPU out of CPU_RUNNING or someone else has
		// already started trying to do that then we need to wait for it to
		// actually happen.
		unsigned int cookie = s_state_run_loop_leave_counter;
		// NOTE: Timeout is a hack to contend with deadlocks in the IO
		//   system to prevent the GUI from freezing. It should be removed.
		s_state_change_cvar.wait(guard, /*std::chrono::seconds(1),*/ [&]
		{
			return s_state_run_loop_leave_counter != cookie;
		});
	}
}

void Pause(bool synchronize)
{
	ChangeStateFromRunning(CPU_STEPPING, synchronize);
}

void Stop(bool synchronize)
{
	ChangeStateFromRunning(CPU_POWERDOWN, synchronize);
}

void LieAboutEnteringRunLoop()
{
	std::lock_guard<std::mutex> guard(s_state_change_lock);
	s_state_run_loop_enter_counter += 1;
}

void LieAboutLeavingRunLoop()
{
	std::lock_guard<std::mutex> guard(s_state_change_lock);
	s_state_run_loop_leave_counter += 1;
	s_state_change_cvar.notify_all();
}

void UpdatePerformanceMonitor(u32 cycles, u32 num_load_stores, u32 num_fp_inst)
{
	switch (MMCR0.PMC1SELECT)
	{
	case 0: // No change
		break;
	case 1: // Processor cycles
		PowerPC::ppcState.spr[SPR_PMC1] += cycles;
		break;
	default:
		break;
	}

	switch (MMCR0.PMC2SELECT)
	{
	case 0: // No change
		break;
	case 1: // Processor cycles
		PowerPC::ppcState.spr[SPR_PMC2] += cycles;
		break;
	case 11: // Number of loads and stores completed
		PowerPC::ppcState.spr[SPR_PMC2] += num_load_stores;
		break;
	default:
		break;
	}

	switch (MMCR1.PMC3SELECT)
	{
	case 0: // No change
		break;
	case 1: // Processor cycles
		PowerPC::ppcState.spr[SPR_PMC3] += cycles;
		break;
	case 11: // Number of FPU instructions completed
		PowerPC::ppcState.spr[SPR_PMC3] += num_fp_inst;
		break;
	default:
		break;
	}

	switch (MMCR1.PMC4SELECT)
	{
	case 0: // No change
		break;
	case 1: // Processor cycles
		PowerPC::ppcState.spr[SPR_PMC4] += cycles;
		break;
	default:
		break;
	}

	if ((MMCR0.PMC1INTCONTROL && (PowerPC::ppcState.spr[SPR_PMC1] & 0x80000000) != 0) ||
		(MMCR0.PMCINTCONTROL && (PowerPC::ppcState.spr[SPR_PMC2] & 0x80000000) != 0) ||
		(MMCR0.PMCINTCONTROL && (PowerPC::ppcState.spr[SPR_PMC3] & 0x80000000) != 0) ||
		(MMCR0.PMCINTCONTROL && (PowerPC::ppcState.spr[SPR_PMC4] & 0x80000000) != 0))
		PowerPC::ppcState.Exceptions |= EXCEPTION_PERFORMANCE_MONITOR;
}

void CheckExceptions()
{
	u32 exceptions = ppcState.Exceptions;

	// Example procedure:
	// set SRR0 to either PC or NPC
	//SRR0 = NPC;
	// save specified MSR bits
	//SRR1 = MSR & 0x87C0FFFF;
	// copy ILE bit to LE
	//MSR |= (MSR >> 16) & 1;
	// clear MSR as specified
	//MSR &= ~0x04EF36; // 0x04FF36 also clears ME (only for machine check exception)
	// set to exception type entry point
	//NPC = 0x00000x00;

	// TODO(delroth): Exception priority is completely wrong here: depending on
	// the instruction class, exceptions should be executed in a given order,
	// which is very different from the one arbitrarily chosen here. See §6.1.5
	// in 6xx_pem.pdf.

	if (exceptions & EXCEPTION_ISI)
	{
		SRR0 = NPC;
		// Page fault occurred
		SRR1 = (MSR & 0x87C0FFFF) | (1 << 30);
		MSR |= (MSR >> 16) & 1;
		MSR &= ~0x04EF36;
		PC = NPC = 0x00000400;

		INFO_LOG(POWERPC, "EXCEPTION_ISI");
		ppcState.Exceptions &= ~EXCEPTION_ISI;
	}
	else if (exceptions & EXCEPTION_PROGRAM)
	{
		SRR0 = PC;
		// say that it's a trap exception
		SRR1 = (MSR & 0x87C0FFFF) | 0x20000;
		MSR |= (MSR >> 16) & 1;
		MSR &= ~0x04EF36;
		PC = NPC = 0x00000700;

		INFO_LOG(POWERPC, "EXCEPTION_PROGRAM");
		ppcState.Exceptions &= ~EXCEPTION_PROGRAM;
	}
	else if (exceptions & EXCEPTION_SYSCALL)
	{
		SRR0 = NPC;
		SRR1 = MSR & 0x87C0FFFF;
		MSR |= (MSR >> 16) & 1;
		MSR &= ~0x04EF36;
		PC = NPC = 0x00000C00;

		INFO_LOG(POWERPC, "EXCEPTION_SYSCALL (PC=%08x)", PC);
		ppcState.Exceptions &= ~EXCEPTION_SYSCALL;
	}
	else if (exceptions & EXCEPTION_FPU_UNAVAILABLE)
	{
		//This happens a lot - GameCube OS uses deferred FPU context switching
		SRR0 = PC; // re-execute the instruction
		SRR1 = MSR & 0x87C0FFFF;
		MSR |= (MSR >> 16) & 1;
		MSR &= ~0x04EF36;
		PC = NPC = 0x00000800;

		INFO_LOG(POWERPC, "EXCEPTION_FPU_UNAVAILABLE");
		ppcState.Exceptions &= ~EXCEPTION_FPU_UNAVAILABLE;
	}
#ifdef ENABLE_MEM_CHECK
	else if (exceptions & EXCEPTION_FAKE_MEMCHECK_HIT)
	{
		ppcState.Exceptions &= ~EXCEPTION_DSI & ~EXCEPTION_FAKE_MEMCHECK_HIT;
	}
#endif
	else if (exceptions & EXCEPTION_DSI)
	{
		SRR0 = PC;
		SRR1 = MSR & 0x87C0FFFF;
		MSR |= (MSR >> 16) & 1;
		MSR &= ~0x04EF36;
		PC = NPC = 0x00000300;
		//DSISR and DAR regs are changed in GenerateDSIException()

		INFO_LOG(POWERPC, "EXCEPTION_DSI");
		ppcState.Exceptions &= ~EXCEPTION_DSI;
	}
	else if (exceptions & EXCEPTION_ALIGNMENT)
	{
		//This never happens ATM
		// perhaps we can get dcb* instructions to use this :p
		SRR0 = PC;
		SRR1 = MSR & 0x87C0FFFF;
		MSR |= (MSR >> 16) & 1;
		MSR &= ~0x04EF36;
		PC = NPC = 0x00000600;

		//TODO crazy amount of DSISR options to check out

		INFO_LOG(POWERPC, "EXCEPTION_ALIGNMENT");
		ppcState.Exceptions &= ~EXCEPTION_ALIGNMENT;
	}

	// EXTERNAL INTERRUPT
	else if (MSR & 0x0008000)  // Handling is delayed until MSR.EE=1.
	{
		if (exceptions & EXCEPTION_EXTERNAL_INT)
		{
			// Pokemon gets this "too early", it hasn't a handler yet
			SRR0 = NPC;
			SRR1 = MSR & 0x87C0FFFF;
			MSR |= (MSR >> 16) & 1;
			MSR &= ~0x04EF36;
			PC = NPC = 0x00000500;

			INFO_LOG(POWERPC, "EXCEPTION_EXTERNAL_INT");
			ppcState.Exceptions &= ~EXCEPTION_EXTERNAL_INT;

			_dbg_assert_msg_(POWERPC, (SRR1 & 0x02) != 0, "EXTERNAL_INT unrecoverable???");
		}
		else if (exceptions & EXCEPTION_PERFORMANCE_MONITOR)
		{
			SRR0 = NPC;
			SRR1 = MSR & 0x87C0FFFF;
			MSR |= (MSR >> 16) & 1;
			MSR &= ~0x04EF36;
			PC = NPC = 0x00000F00;

			INFO_LOG(POWERPC, "EXCEPTION_PERFORMANCE_MONITOR");
			ppcState.Exceptions &= ~EXCEPTION_PERFORMANCE_MONITOR;
		}
		else if (exceptions & EXCEPTION_DECREMENTER)
		{
			SRR0 = NPC;
			SRR1 = MSR & 0x87C0FFFF;
			MSR |= (MSR >> 16) & 1;
			MSR &= ~0x04EF36;
			PC = NPC = 0x00000900;

			INFO_LOG(POWERPC, "EXCEPTION_DECREMENTER");
			ppcState.Exceptions &= ~EXCEPTION_DECREMENTER;
		}
	}
}

void CheckExternalExceptions()
{
	u32 exceptions = ppcState.Exceptions;

	// EXTERNAL INTERRUPT
	if (exceptions && (MSR & 0x0008000))  // Handling is delayed until MSR.EE=1.
	{
		if (exceptions & EXCEPTION_EXTERNAL_INT)
		{
			// Pokemon gets this "too early", it hasn't a handler yet
			SRR0 = NPC;
			SRR1 = MSR & 0x87C0FFFF;
			MSR |= (MSR >> 16) & 1;
			MSR &= ~0x04EF36;
			PC = NPC = 0x00000500;

			INFO_LOG(POWERPC, "EXCEPTION_EXTERNAL_INT");
			ppcState.Exceptions &= ~EXCEPTION_EXTERNAL_INT;

			_dbg_assert_msg_(POWERPC, (SRR1 & 0x02) != 0, "EXTERNAL_INT unrecoverable???");
		}
		else if (exceptions & EXCEPTION_PERFORMANCE_MONITOR)
		{
			SRR0 = NPC;
			SRR1 = MSR & 0x87C0FFFF;
			MSR |= (MSR >> 16) & 1;
			MSR &= ~0x04EF36;
			PC = NPC = 0x00000F00;

			INFO_LOG(POWERPC, "EXCEPTION_PERFORMANCE_MONITOR");
			ppcState.Exceptions &= ~EXCEPTION_PERFORMANCE_MONITOR;
		}
		else if (exceptions & EXCEPTION_DECREMENTER)
		{
			SRR0 = NPC;
			SRR1 = MSR & 0x87C0FFFF;
			MSR |= (MSR >> 16) & 1;
			MSR &= ~0x04EF36;
			PC = NPC = 0x00000900;

			INFO_LOG(POWERPC, "EXCEPTION_DECREMENTER");
			ppcState.Exceptions &= ~EXCEPTION_DECREMENTER;
		}
		else
		{
			_dbg_assert_msg_(POWERPC, 0, "Unknown EXT interrupt: Exceptions == %08x", exceptions);
			ERROR_LOG(POWERPC, "Unknown EXTERNAL INTERRUPT exception: Exceptions == %08x", exceptions);
		}
	}
}

void CheckBreakPoints()
{
	if (PowerPC::breakpoints.IsAddressBreakPoint(PC))
	{
		PowerPC::Pause(false);
		if (PowerPC::breakpoints.IsTempBreakPoint(PC))
			PowerPC::breakpoints.Remove(PC);
	}
}

}  // namespace


// FPSCR update functions

void UpdateFPRF(double dvalue)
{
	FPSCR.FPRF = MathUtil::ClassifyDouble(dvalue);
	//if (FPSCR.FPRF == 0x11)
	//	PanicAlert("QNAN alert");
}
