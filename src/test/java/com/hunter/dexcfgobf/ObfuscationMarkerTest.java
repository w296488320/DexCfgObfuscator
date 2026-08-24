package com.hunter.dexcfgobf;

import com.android.tools.smali.dexlib2.Opcode;
import com.android.tools.smali.dexlib2.builder.Label;
import com.android.tools.smali.dexlib2.builder.MethodImplementationBuilder;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction10t;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction10x;
import com.android.tools.smali.dexlib2.iface.MethodImplementation;

import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class ObfuscationMarkerTest {
    @Test
    public void recognizesExactVersionOneMarker() {
        MethodImplementationBuilder builder = new MethodImplementationBuilder(0);
        Label entry = builder.getLabel("entry");
        ObfuscationMarker.emitV1(builder, entry);
        builder.addLabel("entry");
        builder.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));

        assertTrue(ObfuscationMarker.hasV1(builder.getMethodImplementation()));
    }

    @Test
    public void legacyThreeInstructionShapeCannotTriggerVersionOneRefusal() {
        MethodImplementationBuilder builder = new MethodImplementationBuilder(0);
        Label entry = builder.getLabel("entry");
        builder.addInstruction(new BuilderInstruction10t(Opcode.GOTO, entry));
        builder.addInstruction(new BuilderInstruction10x(Opcode.NOP));
        builder.addInstruction(new BuilderInstruction10t(Opcode.GOTO, entry));
        builder.addLabel("entry");
        builder.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));

        assertFalse(ObfuscationMarker.hasV1(builder.getMethodImplementation()));
    }

    @Test
    public void ordinaryMethodPrefixCannotTriggerVersionOneRefusal() {
        MethodImplementationBuilder builder = new MethodImplementationBuilder(0);
        builder.addInstruction(new BuilderInstruction10x(Opcode.NOP));
        builder.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
        MethodImplementation ordinary = builder.getMethodImplementation();

        assertFalse(ObfuscationMarker.hasV1(ordinary));
        assertFalse(ObfuscationMarker.hasV1(null));
    }
}
