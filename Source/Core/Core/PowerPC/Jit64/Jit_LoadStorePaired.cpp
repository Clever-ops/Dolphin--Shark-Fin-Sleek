// Copyright 2008 Dolphin Emulator Project
// Licensed under GPLv2+
// Refer to the license.txt file included.

// TODO(ector): Tons of pshufb optimization of the loads/stores, for SSSE3+, possibly SSE4, only.
// Should give a very noticeable speed boost to paired single heavy code.

#include "Common/CommonTypes.h"
#include "Common/CPUDetect.h"

#include "Core/PowerPC/Jit64/Jit.h"
#include "Core/PowerPC/Jit64/JitAsm.h"
#include "Core/PowerPC/Jit64/JitRegCache.h"
#include "Core/PowerPC/JitCommon/JitAsmCommon.h"

using namespace Gen;

// The big problem is likely instructions that set the quantizers in the same block.
// We will have to break block after quantizers are written to.
void Jit64::psq_stXX(UGeckoInstruction inst)
{
	INSTRUCTION_START
	JITDISABLE(bJITLoadStorePairedOff);

	s32 offset = inst.SIMM_12;
	bool indexed = inst.OPCD == 4;
	bool update = (inst.OPCD == 61 && offset) || (inst.OPCD == 4 && !!(inst.SUBOP6 & 32));
	int a = inst.RA;
	int b = indexed ? inst.RB : a;
	int s = inst.FS;
	int i = indexed ? inst.Ix : inst.I;
	int w = indexed ? inst.Wx : inst.W;
	FALLBACK_IF(!a);

	auto it = js.constantGqr.find(i);
	bool gqrIsConstant = it != js.constantGqr.end();
	u32 gqrValue = gqrIsConstant ? it->second & 0xffff : 0;

	gpr.Lock(a, b);
	gpr.FlushLockX(RSCRATCH_EXTRA);
	if (update)
		gpr.BindToRegister(a, true, true);
	if (gpr.R(a).IsSimpleReg() && gpr.R(b).IsSimpleReg() && (indexed || offset))
	{
		if (indexed)
			LEA(32, RSCRATCH_EXTRA, MRegSum(gpr.RX(a), gpr.RX(b)));
		else
			LEA(32, RSCRATCH_EXTRA, MDisp(gpr.RX(a), offset));
	}
	else
	{
		MOV(32, R(RSCRATCH_EXTRA), gpr.R(a));
		if (indexed)
			ADD(32, R(RSCRATCH_EXTRA), gpr.R(b));
		else if (offset)
			ADD(32, R(RSCRATCH_EXTRA), Imm32((u32)offset));
	}
	// In memcheck mode, don't update the address until the exception check
	if (update && !jo.memcheck)
		MOV(32, gpr.R(a), R(RSCRATCH_EXTRA));

	if (w)
		CVTSD2SS(XMM0, fpr.R(s)); // one
	else
		CVTPD2PS(XMM0, fpr.R(s)); // pair

	if (gqrIsConstant)
	{
		int type = gqrValue & 0x7;

		// Paired stores (other than w/type zero) don't yield any real change in
		// performance right now, but if we can improve fastmem support this might change
		if (gqrValue == 0)
		{
			if (w)
				GenQuantizedStore(true, (EQuantizeType)type, (gqrValue & 0x3F00) >> 8);
			else
				GenQuantizedStore(false, (EQuantizeType)type, (gqrValue & 0x3F00) >> 8);
		}
		else
		{
			// We know what GQR is here, so we can load RSCRATCH2 and call into the store method directly
			// with just the scale bits.
			MOV(32, R(RSCRATCH2), Imm32(gqrValue & 0x3F00));

			if (w)
				CALL(asm_routines.singleStoreQuantized[type]);
			else
				CALL(asm_routines.pairedStoreQuantized[type]);
		}
	}
	else
	{
		// Some games (e.g. Dirt 2) incorrectly set the unused bits which breaks the lookup table code.
		// Hence, we need to mask out the unused bits. The layout of the GQR register is
		// UU[SCALE]UUUUU[TYPE] where SCALE is 6 bits and TYPE is 3 bits, so we have to AND with
		// 0b0011111100000111, or 0x3F07.
		MOV(32, R(RSCRATCH2), Imm32(0x3F07));
		AND(32, R(RSCRATCH2), PPCSTATE(spr[SPR_GQR0 + i]));
		MOVZX(32, 8, RSCRATCH, R(RSCRATCH2));

		if (w)
			CALLptr(MScaled(RSCRATCH, SCALE_8, (u32)(u64)asm_routines.singleStoreQuantized));
		else
			CALLptr(MScaled(RSCRATCH, SCALE_8, (u32)(u64)asm_routines.pairedStoreQuantized));
	}

	if (update && jo.memcheck)
	{
		if (indexed)
			ADD(32, gpr.R(a), gpr.R(b));
		else
			ADD(32, gpr.R(a), Imm32((u32)offset));
	}
	gpr.UnlockAll();
	gpr.UnlockAllX();
}

void Jit64::psq_lXX(UGeckoInstruction inst)
{
	INSTRUCTION_START
	JITDISABLE(bJITLoadStorePairedOff);

	s32 offset = inst.SIMM_12;
	bool indexed = inst.OPCD == 4;
	bool update = (inst.OPCD == 57 && offset) || (inst.OPCD == 4 && !!(inst.SUBOP6 & 32));
	int a = inst.RA;
	int b = indexed ? inst.RB : a;
	int s = inst.FS;
	int i = indexed ? inst.Ix : inst.I;
	int w = indexed ? inst.Wx : inst.W;
	FALLBACK_IF(!a);

	auto it = js.constantGqr.find(i);
	bool gqrIsConstant = it != js.constantGqr.end();
	u32 gqrValue = gqrIsConstant ? it->second >> 16 : 0;

	gpr.Lock(a, b);

	gpr.FlushLockX(RSCRATCH_EXTRA);
	gpr.BindToRegister(a, true, update);
	fpr.BindToRegister(s, false, true);
	if (gpr.R(a).IsSimpleReg() && gpr.R(b).IsSimpleReg() && (indexed || offset))
	{
		if (indexed)
			LEA(32, RSCRATCH_EXTRA, MRegSum(gpr.RX(a), gpr.RX(b)));
		else
			LEA(32, RSCRATCH_EXTRA, MDisp(gpr.RX(a), offset));
	}
	else
	{
		MOV(32, R(RSCRATCH_EXTRA), gpr.R(a));
		if (indexed)
			ADD(32, R(RSCRATCH_EXTRA), gpr.R(b));
		else if (offset)
			ADD(32, R(RSCRATCH_EXTRA), Imm32((u32)offset));
	}
	// In memcheck mode, don't update the address until the exception check
	if (update && !jo.memcheck)
		MOV(32, gpr.R(a), R(RSCRATCH_EXTRA));

	if (gqrIsConstant)
	{
		GenQuantizedLoad(w == 1, (EQuantizeType)(gqrValue & 0x7), (gqrValue & 0x3F00) >> 8);
	}
	else
	{
		MOV(32, R(RSCRATCH2), Imm32(0x3F07));

		// Get the high part of the GQR register
		OpArg gqr = PPCSTATE(spr[SPR_GQR0 + i]);
		gqr.AddMemOffset(2);

		AND(32, R(RSCRATCH2), gqr);
		MOVZX(32, 8, RSCRATCH, R(RSCRATCH2));

		CALLptr(MScaled(RSCRATCH, SCALE_8, (u32)(u64)(&asm_routines.pairedLoadQuantized[w * 8])));
	}

	CVTPS2PD(fpr.RX(s), R(XMM0));
	if (update && jo.memcheck)
	{
		if (indexed)
			ADD(32, gpr.R(a), gpr.R(b));
		else
			ADD(32, gpr.R(a), Imm32((u32)offset));
	}

	gpr.UnlockAll();
	gpr.UnlockAllX();
}
