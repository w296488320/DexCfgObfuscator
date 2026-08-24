package com.hunter.dexcfgobf;

import com.android.tools.smali.dexlib2.Opcode;
import com.android.tools.smali.dexlib2.iface.Method;
import com.android.tools.smali.dexlib2.iface.MethodImplementation;
import com.android.tools.smali.dexlib2.iface.instruction.Instruction;

/** JSON 报告中的方法级记录。 */
final class MethodReport {
    final String dex;
    final String owner;
    final String name;
    final String descriptor;
    final String mode;
    final String reason;
    final String template;
    final int instructionsBefore;
    final int instructionsAfter;
    final int codeUnitsBefore;
    final int codeUnitsAfter;
    final int registersBefore;
    final int registersAfter;
    final boolean hasTry;
    final boolean hasSwitch;
    final boolean hasArrayPayload;
    final boolean registerTypesSeparated;
    final int addedRegisters;
    final int switchesPadded;
    final int switchCasesBefore;
    final int switchCasesAfter;
    final int fakeSwitchCases;
    final int symbolSwitchCases;
    final int dispatcherRegions;
    final int reachableAliasCases;
    final int stateShareRegisters;

    private MethodReport(String dex, Method method, TransformationOutcome outcome,
                         MethodImplementation before, MethodImplementation after) {
        this.dex = dex;
        this.owner = method.getDefiningClass();
        this.name = method.getName();
        StringBuilder d = new StringBuilder("(");
        for (CharSequence p : method.getParameterTypes()) d.append(p);
        this.descriptor = d.append(')').append(method.getReturnType()).toString();
        this.mode = outcome.mode.name().toLowerCase(java.util.Locale.US);
        this.reason = outcome.reason.name().toLowerCase(java.util.Locale.US);
        this.template = outcome.template;
        this.instructionsBefore = count(before);
        this.instructionsAfter = after == null ? instructionsBefore : count(after);
        this.codeUnitsBefore = PostTransformBudget.codeUnits(before);
        this.codeUnitsAfter = after == null ? codeUnitsBefore : PostTransformBudget.codeUnits(after);
        this.registersBefore = before.getRegisterCount();
        this.registersAfter = after == null ? registersBefore : after.getRegisterCount();
        this.hasTry = before.getTryBlocks() != null && !before.getTryBlocks().isEmpty();
        boolean sw = false;
        boolean arr = false;
        for (Instruction instruction : before.getInstructions()) {
            Opcode op = instruction.getOpcode();
            sw |= op == Opcode.PACKED_SWITCH || op == Opcode.SPARSE_SWITCH
                    || op == Opcode.PACKED_SWITCH_PAYLOAD || op == Opcode.SPARSE_SWITCH_PAYLOAD;
            arr |= op == Opcode.FILL_ARRAY_DATA || op == Opcode.ARRAY_PAYLOAD;
        }
        this.hasSwitch = sw;
        this.hasArrayPayload = arr;
        this.registerTypesSeparated = outcome.registerTypesSeparated;
        this.addedRegisters = outcome.addedRegisters;
        this.switchesPadded = outcome.switchesPadded;
        this.switchCasesBefore = outcome.switchCasesBefore;
        this.switchCasesAfter = outcome.switchCasesAfter;
        this.fakeSwitchCases = outcome.fakeSwitchCases;
        this.symbolSwitchCases = outcome.symbolSwitchCases;
        this.dispatcherRegions = outcome.dispatcherRegions;
        this.reachableAliasCases = outcome.reachableAliasCases;
        this.stateShareRegisters = outcome.stateShareRegisters;
    }

    private MethodReport(String dex, String owner, String name, String descriptor,
                         String mode, String reason, String template,
                         int instructionsBefore, int instructionsAfter,
                         int codeUnitsBefore, int codeUnitsAfter,
                         int registersBefore, int registersAfter,
                         boolean hasTry, boolean hasSwitch, boolean hasArrayPayload,
                         boolean registerTypesSeparated, int addedRegisters,
                         int switchesPadded, int switchCasesBefore, int switchCasesAfter,
                         int fakeSwitchCases, int symbolSwitchCases, int dispatcherRegions,
                         int reachableAliasCases, int stateShareRegisters) {
        this.dex = dex;
        this.owner = owner;
        this.name = name;
        this.descriptor = descriptor;
        this.mode = mode;
        this.reason = reason;
        this.template = template;
        this.instructionsBefore = instructionsBefore;
        this.instructionsAfter = instructionsAfter;
        this.codeUnitsBefore = codeUnitsBefore;
        this.codeUnitsAfter = codeUnitsAfter;
        this.registersBefore = registersBefore;
        this.registersAfter = registersAfter;
        this.hasTry = hasTry;
        this.hasSwitch = hasSwitch;
        this.hasArrayPayload = hasArrayPayload;
        this.registerTypesSeparated = registerTypesSeparated;
        this.addedRegisters = addedRegisters;
        this.switchesPadded = switchesPadded;
        this.switchCasesBefore = switchCasesBefore;
        this.switchCasesAfter = switchCasesAfter;
        this.fakeSwitchCases = fakeSwitchCases;
        this.symbolSwitchCases = symbolSwitchCases;
        this.dispatcherRegions = dispatcherRegions;
        this.reachableAliasCases = reachableAliasCases;
        this.stateShareRegisters = stateShareRegisters;
    }

    static MethodReport of(String dex, Method method, TransformationOutcome outcome,
                           MethodImplementation before, MethodImplementation after) {
        return new MethodReport(dex, method, outcome, before, after);
    }

    /** Recreates an immutable report from a previously validated build-evidence record. */
    static MethodReport restore(String dex, String owner, String name, String descriptor,
                                String mode, String reason, String template,
                                int instructionsBefore, int instructionsAfter,
                                int codeUnitsBefore, int codeUnitsAfter,
                                int registersBefore, int registersAfter,
                                boolean hasTry, boolean hasSwitch, boolean hasArrayPayload,
                                boolean registerTypesSeparated, int addedRegisters,
                                int switchesPadded, int switchCasesBefore, int switchCasesAfter,
                                int fakeSwitchCases, int symbolSwitchCases, int dispatcherRegions,
                                int reachableAliasCases, int stateShareRegisters) {
        return new MethodReport(dex, owner, name, descriptor, mode, reason, template,
                instructionsBefore, instructionsAfter, codeUnitsBefore, codeUnitsAfter,
                registersBefore, registersAfter, hasTry, hasSwitch, hasArrayPayload,
                registerTypesSeparated, addedRegisters, switchesPadded, switchCasesBefore,
                switchCasesAfter, fakeSwitchCases, symbolSwitchCases, dispatcherRegions,
                reachableAliasCases, stateShareRegisters);
    }

    private static int count(MethodImplementation implementation) {
        int count = 0;
        for (Instruction ignored : implementation.getInstructions()) count++;
        return count;
    }
}
