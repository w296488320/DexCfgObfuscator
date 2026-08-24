package com.hunter.dexcfgobf.string;

import org.junit.Test;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.lang.reflect.Field;
import java.util.Base64;
import java.util.Collections;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

/** Documents the unavoidable JVM initialization boundary of protected ConstantValue fields. */
public class StringStaticFieldReentryTest {
    private static final String FIXTURE_BINARY = "fixture.ReentrantStaticFieldFixture";
    private static final String FIXTURE_INTERNAL = "fixture/ReentrantStaticFieldFixture";

    @Test
    public void customDecryptorReentrySeesDefaultValueButFinalFieldsStillInitialize() throws Exception {
        StringEncryptionContext context = StringEncryptionContext.create(
                null, null, null, Collections.singletonList("fixture"),
                Collections.emptyList(), ReentrantBridge.class.getName(),
                StringEncryptionMode.BYTES, 7L, 4096, false, true, false, false, true);
        byte[] transformed = transform(fixture(), context);
        Class<?> type = new FixtureLoader().define(FIXTURE_BINARY, transformed);
        Field first = type.getField("FIRST");
        Field second = type.getField("SECOND");
        AtomicReference<Object> valueSeenDuringReentry = new AtomicReference<>();

        ReentrantBridge.beforeFirstDecrypt = () -> {
            try {
                valueSeenDuringReentry.set(second.get(null));
            } catch (ReflectiveOperationException failure) {
                throw new AssertionError(failure);
            }
        };
        try {
            assertEquals("first-protected-value", first.get(null));
        } finally {
            ReentrantBridge.beforeFirstDecrypt = null;
        }

        assertNull("same-thread class-initialization re-entry observes the JVM default",
                valueSeenDuringReentry.get());
        assertEquals("second-protected-value", second.get(null));
    }

    private static byte[] transform(byte[] original, StringEncryptionContext context) {
        ClassReader reader = new ClassReader(original);
        ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
        reader.accept(new StringEncryptionClassVisitor(context, writer), 0);
        return writer.toByteArray();
    }

    private static byte[] fixture() {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC, FIXTURE_INTERNAL, null,
                "java/lang/Object", null);
        writer.visitField(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_FINAL,
                "FIRST", "Ljava/lang/String;", null, "first-protected-value").visitEnd();
        writer.visitField(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_FINAL,
                "SECOND", "Ljava/lang/String;", null, "second-protected-value").visitEnd();
        MethodVisitor constructor = writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V",
                null, null);
        constructor.visitCode();
        constructor.visitVarInsn(Opcodes.ALOAD, 0);
        constructor.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>",
                "()V", false);
        constructor.visitInsn(Opcodes.RETURN);
        constructor.visitMaxs(1, 1);
        constructor.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    public static final class ReentrantBridge {
        static volatile Runnable beforeFirstDecrypt;

        public static String decrypt(byte[] value, byte[] key) {
            Runnable hook = beforeFirstDecrypt;
            if (hook != null) {
                beforeFirstDecrypt = null;
                hook.run();
            }
            return new StreamXorStringCipher().decrypt(value, key).intern();
        }

        public static String decrypt(String value, String key) {
            return decrypt(Base64.getDecoder().decode(value), Base64.getDecoder().decode(key));
        }
    }

    private static final class FixtureLoader extends ClassLoader {
        FixtureLoader() {
            super(StringStaticFieldReentryTest.class.getClassLoader());
        }

        Class<?> define(String name, byte[] bytes) {
            return defineClass(name, bytes, 0, bytes.length);
        }
    }
}
