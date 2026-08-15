package com.hunter.dexcfgobf;

import com.android.tools.smali.dexlib2.AccessFlags;
import com.android.tools.smali.dexlib2.Opcode;
import com.android.tools.smali.dexlib2.Opcodes;
import com.android.tools.smali.dexlib2.analysis.ClassPath;
import com.android.tools.smali.dexlib2.analysis.DexClassProvider;
import com.android.tools.smali.dexlib2.builder.Label;
import com.android.tools.smali.dexlib2.builder.MethodImplementationBuilder;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction10t;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction10x;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction11n;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction11x;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction21c;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction21t;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction22c;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction35c;
import com.android.tools.smali.dexlib2.iface.MethodImplementation;
import com.android.tools.smali.dexlib2.iface.instruction.OneRegisterInstruction;
import com.android.tools.smali.dexlib2.immutable.ImmutableClassDef;
import com.android.tools.smali.dexlib2.immutable.ImmutableDexFile;
import com.android.tools.smali.dexlib2.immutable.ImmutableMethod;
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableStringReference;
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableMethodReference;
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableTypeReference;
import com.android.tools.smali.dexlib2.writer.io.FileDataStore;
import com.android.tools.smali.dexlib2.writer.pool.DexPool;

import org.junit.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.LinkedHashSet;

import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class VerifierTypeSeparatorTest {

    @Test
    public void separatesReusedReferenceRegisterThenStrongFlattensAndVerifiesDex() throws Exception {
        MethodImplementation source = referenceReuseImplementation();
        ImmutableMethod original = method(source);
        ImmutableClassDef originalClass = classDef(original);
        ImmutableDexFile originalDex = new ImmutableDexFile(Opcodes.getDefault(),
                Collections.singleton(originalClass));
        ClassPath classPath = new ClassPath(Collections.singletonList(
                new DexClassProvider(originalDex)), false, ClassPath.NOT_ART);

        ObfuscatorConfig config = new ObfuscatorConfig();
        config.depth = 2;
        VerifierTypeSeparator.Result separated =
                new VerifierTypeSeparator(classPath, config).separate(original);

        assertNotNull("verifier analysis should prove this non-overlapping reuse", separated);
        assertTrue("at least String/byte[] lifetimes must be split", separated.addedRegisters >= 1);
        int stringRegister = -1;
        int arrayRegister = -1;
        for (com.android.tools.smali.dexlib2.iface.instruction.Instruction instruction
                : separated.implementation.getInstructions()) {
            if (instruction.getOpcode() == Opcode.CONST_STRING && stringRegister < 0) {
                stringRegister = ((OneRegisterInstruction) instruction).getRegisterA();
            } else if (instruction.getOpcode() == Opcode.NEW_ARRAY) {
                arrayRegister = ((OneRegisterInstruction) instruction).getRegisterA();
            }
        }
        assertTrue(stringRegister >= 0 && arrayRegister >= 0);
        assertNotEquals("incompatible reference lifetimes need distinct physical registers",
                stringRegister, arrayRegister);

        ObfuscatorStats stats = new ObfuscatorStats();
        MethodImplementation flattened = new CfgFlattener(config, ObfuscatorLogger.STDOUT, stats)
                .flatten(original, separated.implementation, true, separated.addedRegisters);
        assertNotNull("type-separated method should enter strong flattening", flattened);
        assertTrue(stats.methodsFlattened == 1);

        ImmutableMethod transformed = method(flattened);
        DexPool pool = new DexPool(Opcodes.getDefault());
        pool.internClass(classDef(transformed));
        Path dex = Files.createTempFile("dex-cfg-verifier-separated-", ".dex");
        try {
            pool.writeTo(new FileDataStore(dex.toFile()));
            DexStructuralVerifier.verify(dex.toFile());
        } finally {
            Files.deleteIfExists(dex);
        }
    }

    @Test
    public void rejectsFloatDeclaredOnlyByExternalMethodSignature() {
        MethodImplementationBuilder b = new MethodImplementationBuilder(1);
        b.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 0, 0));
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 1,
                0, 0, 0, 0, 0,
                new ImmutableMethodReference("Lexternal/Chart;", "setRadius",
                        Collections.singletonList("F"), "V")));
        b.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
        ImmutableMethod method = method(b.getMethodImplementation());
        ImmutableDexFile dex = new ImmutableDexFile(Opcodes.getDefault(),
                Collections.singleton(classDef(method)));
        ClassPath classPath = new ClassPath(Collections.singletonList(
                new DexClassProvider(dex)), false, ClassPath.NOT_ART);

        assertNull("external float signatures must fall back to CFG-preserving reorder",
                new VerifierTypeSeparator(classPath, new ObfuscatorConfig()).separate(method));
    }

    @Test
    public void rejectsNarrowPrimitiveDeclaredByExternalMethodSignature() {
        MethodImplementationBuilder b = new MethodImplementationBuilder(1);
        b.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 0, 1));
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 1,
                0, 0, 0, 0, 0,
                new ImmutableMethodReference("Lexternal/Parser;", "consumeByte",
                        Collections.singletonList("B"), "Z")));
        b.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
        ImmutableMethod method = method(b.getMethodImplementation());
        ImmutableDexFile dex = new ImmutableDexFile(Opcodes.getDefault(),
                Collections.singleton(classDef(method)));
        ClassPath classPath = new ClassPath(Collections.singletonList(
                new DexClassProvider(dex)), false, ClassPath.NOT_ART);

        assertNull("boolean/byte signatures require narrow-type SSA and must use safe reorder",
                new VerifierTypeSeparator(classPath, new ObfuscatorConfig()).separate(method));
    }

    private static MethodImplementation referenceReuseImplementation() {
        MethodImplementationBuilder b = new MethodImplementationBuilder(2);
        Label bytes = b.getLabel("Bytes");
        Label done = b.getLabel("Done");
        b.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 0, 0));
        b.addInstruction(new BuilderInstruction21t(Opcode.IF_EQZ, 0, bytes));
        b.addInstruction(new BuilderInstruction21c(Opcode.CONST_STRING, 1,
                new ImmutableStringReference("direct")));
        b.addInstruction(new BuilderInstruction10t(Opcode.GOTO, done));
        b.addLabel("Bytes");
        b.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 0, 1));
        b.addInstruction(new BuilderInstruction22c(Opcode.NEW_ARRAY, 1, 0,
                new ImmutableTypeReference("[B")));
        b.addInstruction(new BuilderInstruction21c(Opcode.CONST_STRING, 1,
                new ImmutableStringReference("converted")));
        b.addLabel("Done");
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 1));
        return b.getMethodImplementation();
    }

    private static ImmutableMethod method(MethodImplementation implementation) {
        return new ImmutableMethod("Lcom/example/Test;", "referenceReuse",
                Collections.emptyList(), "Ljava/lang/String;",
                AccessFlags.PUBLIC.getValue() | AccessFlags.STATIC.getValue(),
                Collections.emptySet(), Collections.emptySet(), implementation);
    }

    private static ImmutableClassDef classDef(ImmutableMethod method) {
        return new ImmutableClassDef("Lcom/example/Test;", AccessFlags.PUBLIC.getValue(),
                "Ljava/lang/Object;", Collections.emptyList(), "Test.java",
                Collections.emptySet(), Collections.emptyList(), Collections.emptyList(),
                new LinkedHashSet<>(Collections.singleton(method)), Collections.emptySet());
    }
}
