package com.hunter.dexcfgobf;

import com.android.tools.smali.dexlib2.Opcode;
import com.android.tools.smali.dexlib2.builder.BuilderInstruction;
import com.android.tools.smali.dexlib2.builder.BuilderOffsetInstruction;
import com.android.tools.smali.dexlib2.builder.Label;
import com.android.tools.smali.dexlib2.builder.MethodImplementationBuilder;
import com.android.tools.smali.dexlib2.builder.MutableMethodImplementation;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction10x;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction30t;
import com.android.tools.smali.dexlib2.iface.MethodImplementation;

import java.util.List;

/**
 * Versioned, register-free marker shared by strong flattening and safe block reordering.
 *
 * <p>V1 is an unreachable 10-instruction prefix with four {@code goto/32} instructions targeting
 * the same entry and NOP runs of lengths 1, 2, and 3 between them. Requiring the exact opcode,
 * run-length, target, and position pattern makes accidental source-code collisions negligible while
 * remaining verifier-safe even for a zero-register method.</p>
 */
final class ObfuscationMarker {
    static final int V1_INSTRUCTION_COUNT = 10;

    private ObfuscationMarker() {
    }

    static void emitV1(MethodImplementationBuilder out, Label transformedEntry) {
        addGoto(out, transformedEntry);
        addNops(out, 1);
        addGoto(out, transformedEntry);
        addNops(out, 2);
        addGoto(out, transformedEntry);
        addNops(out, 3);
        addGoto(out, transformedEntry);
    }

    static boolean hasV1(MethodImplementation implementation) {
        if (implementation == null) return false;
        MutableMethodImplementation work = new MutableMethodImplementation(implementation);
        List<BuilderInstruction> instructions = work.getInstructions();
        if (instructions.size() < V1_INSTRUCTION_COUNT
                || instructions.get(0).getOpcode() != Opcode.GOTO_32
                || instructions.get(1).getOpcode() != Opcode.NOP
                || instructions.get(2).getOpcode() != Opcode.GOTO_32
                || instructions.get(3).getOpcode() != Opcode.NOP
                || instructions.get(4).getOpcode() != Opcode.NOP
                || instructions.get(5).getOpcode() != Opcode.GOTO_32
                || instructions.get(6).getOpcode() != Opcode.NOP
                || instructions.get(7).getOpcode() != Opcode.NOP
                || instructions.get(8).getOpcode() != Opcode.NOP
                || instructions.get(9).getOpcode() != Opcode.GOTO_32) {
            return false;
        }
        Integer expectedTarget = targetIndex(instructions.get(0));
        return expectedTarget != null
                && expectedTarget >= V1_INSTRUCTION_COUNT
                && expectedTarget.equals(targetIndex(instructions.get(2)))
                && expectedTarget.equals(targetIndex(instructions.get(5)))
                && expectedTarget.equals(targetIndex(instructions.get(9)));
    }

    private static void addGoto(MethodImplementationBuilder out, Label target) {
        out.addInstruction(new BuilderInstruction30t(Opcode.GOTO_32, target));
    }

    private static void addNops(MethodImplementationBuilder out, int count) {
        for (int i = 0; i < count; i++) {
            out.addInstruction(new BuilderInstruction10x(Opcode.NOP));
        }
    }

    private static Integer targetIndex(BuilderInstruction instruction) {
        if (!(instruction instanceof BuilderOffsetInstruction)) return null;
        Label target = ((BuilderOffsetInstruction) instruction).getTarget();
        if (target == null || target.getLocation() == null) return null;
        return target.getLocation().getIndex();
    }
}
