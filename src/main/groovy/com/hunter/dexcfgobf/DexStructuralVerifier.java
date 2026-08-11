package com.hunter.dexcfgobf;

import com.android.tools.smali.dexlib2.Opcode;
import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile;
import com.android.tools.smali.dexlib2.iface.ClassDef;
import com.android.tools.smali.dexlib2.iface.ExceptionHandler;
import com.android.tools.smali.dexlib2.iface.Method;
import com.android.tools.smali.dexlib2.iface.MethodImplementation;
import com.android.tools.smali.dexlib2.iface.TryBlock;
import com.android.tools.smali.dexlib2.iface.instruction.FiveRegisterInstruction;
import com.android.tools.smali.dexlib2.iface.instruction.Instruction;
import com.android.tools.smali.dexlib2.iface.instruction.OffsetInstruction;
import com.android.tools.smali.dexlib2.iface.instruction.OneRegisterInstruction;
import com.android.tools.smali.dexlib2.iface.instruction.RegisterRangeInstruction;
import com.android.tools.smali.dexlib2.iface.instruction.SwitchElement;
import com.android.tools.smali.dexlib2.iface.instruction.SwitchPayload;
import com.android.tools.smali.dexlib2.iface.instruction.ThreeRegisterInstruction;
import com.android.tools.smali.dexlib2.iface.instruction.TwoRegisterInstruction;
import com.android.tools.smali.dexlib2.iface.instruction.VariableRegisterInstruction;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 写回前的 fail-closed DEX 结构验证。
 *
 * dexlib2 能保证序列化格式，但不会替调用方证明重新连接后的分支、payload、handler 和
 * move-result 仍满足 ART 约束。因此这里在临时文件上重新解析并逐方法检查；失败即禁止提交。
 */
final class DexStructuralVerifier {
    private DexStructuralVerifier() {}

    static void verify(File dexFile) throws Exception {
        DexBackedDexFile dex;
        try (BufferedInputStream in = new BufferedInputStream(new FileInputStream(dexFile))) {
            // 必须按 DEX 文件头自动选择 opcode 表。dex.039 的 0xfa/0xfb 是
            // invoke-polymorphic；若按 API 20 解码，会被误判为旧 odex quick 指令，
            // 进而对合法的 move-result 产生假阳性。
            dex = DexBackedDexFile.fromInputStream(null, in);
        }
        for (ClassDef classDef : dex.getClasses()) {
            for (Method method : classDef.getMethods()) {
                MethodImplementation implementation = method.getImplementation();
                if (implementation != null) verifyMethod(method, implementation);
            }
        }
    }

    private static void verifyMethod(Method method, MethodImplementation implementation) {
        String id = method.getDefiningClass() + "->" + method.getName();
        int registerCount = implementation.getRegisterCount();
        List<Instruction> instructions = new ArrayList<>();
        Map<Integer, Instruction> byAddress = new HashMap<>();
        Map<Integer, Integer> switchPayloadUsers = new HashMap<>();
        Set<Integer> handlerAddresses = new HashSet<>();

        int address = 0;
        for (Instruction instruction : implementation.getInstructions()) {
            if (byAddress.put(address, instruction) != null) fail(id, "duplicate instruction address " + address);
            instructions.add(instruction);
            verifyRegisters(id, instruction, registerCount);
            address += instruction.getCodeUnits();
        }
        final int codeUnits = address;

        address = 0;
        Instruction previous = null;
        for (Instruction instruction : instructions) {
            Opcode opcode = instruction.getOpcode();
            if (isMoveResult(opcode) && (previous == null || !previous.getOpcode().setsResult())) {
                fail(id, opcode + " is not adjacent to a result-producing instruction at " + address);
            }
            if (instruction instanceof OffsetInstruction) {
                int target = address + ((OffsetInstruction) instruction).getCodeOffset();
                Instruction targetInstruction = byAddress.get(target);
                if (targetInstruction == null) fail(id, opcode + " targets non-instruction address " + target);
                if (target == address && opcode != Opcode.GOTO_32) {
                    fail(id, opcode + " illegally branches to itself at " + address);
                }
                if (opcode == Opcode.PACKED_SWITCH || opcode == Opcode.SPARSE_SWITCH) {
                    Opcode expected = opcode == Opcode.PACKED_SWITCH
                            ? Opcode.PACKED_SWITCH_PAYLOAD : Opcode.SPARSE_SWITCH_PAYLOAD;
                    if (targetInstruction.getOpcode() != expected) {
                        fail(id, opcode + " targets " + targetInstruction.getOpcode() + " instead of " + expected);
                    }
                    if ((target & 1) != 0) fail(id, "switch payload is not 4-byte aligned at " + target);
                    Integer old = switchPayloadUsers.put(target, address);
                    if (old != null && old != address) fail(id, "switch payload is shared by multiple switch instructions");
                } else if (opcode == Opcode.FILL_ARRAY_DATA) {
                    if (targetInstruction.getOpcode() != Opcode.ARRAY_PAYLOAD) {
                        fail(id, "fill-array-data targets " + targetInstruction.getOpcode());
                    }
                    if ((target & 1) != 0) fail(id, "array payload is not 4-byte aligned at " + target);
                } else if (isExecutableBranch(opcode)) {
                    if (isPayload(targetInstruction.getOpcode())) {
                        fail(id, opcode + " branches into payload at " + target);
                    }
                    if (isMoveResult(targetInstruction.getOpcode())
                            || targetInstruction.getOpcode() == Opcode.MOVE_EXCEPTION) {
                        fail(id, opcode + " branches into verifier-only instruction "
                                + targetInstruction.getOpcode() + " at " + target);
                    }
                }
            }
            previous = instruction;
            address += instruction.getCodeUnits();
        }

        int previousTryEnd = -1;
        for (TryBlock<? extends ExceptionHandler> tryBlock : implementation.getTryBlocks()) {
            int start = tryBlock.getStartCodeAddress();
            int end = start + tryBlock.getCodeUnitCount();
            if (start < 0 || start >= end || end > codeUnits || !byAddress.containsKey(start)
                    || (end != codeUnits && !byAddress.containsKey(end))) {
                fail(id, "invalid try range [" + start + "," + end + ")");
            }
            if (start < previousTryEnd) fail(id, "try ranges overlap or are out of order");
            previousTryEnd = end;
            for (ExceptionHandler handler : tryBlock.getExceptionHandlers()) {
                int handlerAddress = handler.getHandlerCodeAddress();
                Instruction first = byAddress.get(handlerAddress);
                // 被捕获的异常对象可以被忽略，此时合法的 R8 handler 会省略 move-exception。
                // 若方法确实出现 move-exception，下面仍严格要求它只能位于某个 handler 入口。
                if (first == null) fail(id, "handler targets non-instruction address " + handlerAddress);
                handlerAddresses.add(handlerAddress);
            }
        }

        address = 0;
        for (Instruction instruction : instructions) {
            if (instruction.getOpcode() == Opcode.MOVE_EXCEPTION && !handlerAddresses.contains(address)) {
                fail(id, "move-exception is not a handler entry at " + address);
            }
            if (instruction instanceof SwitchPayload) {
                Integer switchAddress = switchPayloadUsers.get(address);
                if (switchAddress == null) fail(id, "orphan switch payload at " + address);
                int previousKey = Integer.MIN_VALUE;
                boolean first = true;
                for (SwitchElement element : ((SwitchPayload) instruction).getSwitchElements()) {
                    if (!first && element.getKey() <= previousKey) fail(id, "switch keys are not strictly sorted");
                    first = false;
                    previousKey = element.getKey();
                    int target = switchAddress + element.getOffset();
                    Instruction targetInstruction = byAddress.get(target);
                    if (targetInstruction == null || isPayload(targetInstruction.getOpcode())
                            || isMoveResult(targetInstruction.getOpcode())
                            || targetInstruction.getOpcode() == Opcode.MOVE_EXCEPTION) {
                        fail(id, "invalid switch case target " + target);
                    }
                }
            }
            address += instruction.getCodeUnits();
        }
    }

    private static void verifyRegisters(String id, Instruction instruction, int registerCount) {
        if (instruction instanceof RegisterRangeInstruction) {
            RegisterRangeInstruction range = (RegisterRangeInstruction) instruction;
            long end = (long) range.getStartRegister() + range.getRegisterCount();
            if (range.getStartRegister() < 0 || end > registerCount) {
                fail(id, instruction.getOpcode() + " range exceeds registers: " + end + "/" + registerCount);
            }
            return;
        }
        if (instruction instanceof FiveRegisterInstruction) {
            FiveRegisterInstruction five = (FiveRegisterInstruction) instruction;
            int count = ((VariableRegisterInstruction) instruction).getRegisterCount();
            int[] registers = {five.getRegisterC(), five.getRegisterD(), five.getRegisterE(),
                    five.getRegisterF(), five.getRegisterG()};
            for (int i = 0; i < count; i++) checkRegister(id, instruction, registers[i], registerCount);
            return;
        }
        if (instruction instanceof OneRegisterInstruction) {
            checkRegister(id, instruction, ((OneRegisterInstruction) instruction).getRegisterA(), registerCount);
        }
        if (instruction instanceof TwoRegisterInstruction) {
            checkRegister(id, instruction, ((TwoRegisterInstruction) instruction).getRegisterB(), registerCount);
        }
        if (instruction instanceof ThreeRegisterInstruction) {
            checkRegister(id, instruction, ((ThreeRegisterInstruction) instruction).getRegisterC(), registerCount);
        }
    }

    private static void checkRegister(String id, Instruction instruction, int register, int registerCount) {
        if (register < 0 || register >= registerCount) {
            fail(id, instruction.getOpcode() + " uses v" + register + " with registerCount=" + registerCount);
        }
        if (instruction.getOpcode().setsWideRegister()
                && instruction instanceof OneRegisterInstruction
                && ((OneRegisterInstruction) instruction).getRegisterA() + 1 >= registerCount) {
            fail(id, instruction.getOpcode() + " wide destination exceeds register file");
        }
    }

    private static boolean isMoveResult(Opcode opcode) {
        return opcode == Opcode.MOVE_RESULT || opcode == Opcode.MOVE_RESULT_WIDE
                || opcode == Opcode.MOVE_RESULT_OBJECT;
    }

    private static boolean isPayload(Opcode opcode) {
        return opcode == Opcode.PACKED_SWITCH_PAYLOAD || opcode == Opcode.SPARSE_SWITCH_PAYLOAD
                || opcode == Opcode.ARRAY_PAYLOAD;
    }

    private static boolean isExecutableBranch(Opcode opcode) {
        return opcode == Opcode.GOTO || opcode == Opcode.GOTO_16 || opcode == Opcode.GOTO_32
                || opcode.name.startsWith("if-");
    }

    private static void fail(String method, String message) {
        throw new IllegalStateException(method + ": " + message);
    }
}
