/*
 * Portions adapted from MegatronKing/StringFog's StringFogClassVisitor.
 * Copyright (C) 2017, Megatron King
 * Modifications Copyright (C) 2026 DexCfgObfuscator contributors
 *
 * Licensed under the Apache License, Version 2.0. See the repository LICENSE file or
 * https://www.apache.org/licenses/LICENSE-2.0 for the complete terms.
 */
package com.hunter.dexcfgobf.string;

import org.gradle.api.logging.Logger;
import org.gradle.api.logging.Logging;
import org.objectweb.asm.AnnotationVisitor;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ConstantDynamic;
import org.objectweb.asm.FieldVisitor;
import org.objectweb.asm.Handle;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.RecordComponentVisitor;
import org.objectweb.asm.commons.CodeSizeEvaluator;
import org.objectweb.asm.tree.MethodNode;

import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/** 将可执行字符串常量替换为密文和生成桥的 decrypt 调用。 */
final class StringEncryptionClassVisitor extends ClassVisitor {
    private static final Logger LOGGER = Logging.getLogger(StringEncryptionClassVisitor.class);
    /** JVMS 4.7.3: Code.code_length must be less than 65536. */
    private static final int MAX_JVM_CODE_BYTES = 65_535;
    private static final String STRING_DESCRIPTOR = "Ljava/lang/String;";
    private static final String IGNORE_ANNOTATION =
            "Lcom/hunter/dexcfgobf/annotation/StringEncryptionIgnore;";
    private static final String LEGACY_IGNORE_ANNOTATION =
            "Lcom/github/megatronking/stringfog/annotation/StringFogIgnore;";
    private final StringEncryptionContext context;
    private final List<StaticFieldPlan> staticFields = new ArrayList<>();
    private final List<RecordObjectMethodsMetadata.Component> recordComponents =
            new ArrayList<>();
    private String className;
    private boolean recordClass;
    private boolean ignored;
    private boolean hasClassInitializer;

    StringEncryptionClassVisitor(StringEncryptionContext context, ClassVisitor delegate) {
        super(Opcodes.ASM9, delegate);
        this.context = context;
    }

    @Override
    public void visit(int version, int access, String name, String signature,
                      String superName, String[] interfaces) {
        className = name;
        recordClass = (access & Opcodes.ACC_RECORD) != 0
                && RecordObjectMethodsMetadata.RECORD_SUPER.equals(superName);
        context.recordClassVisit(name);
        super.visit(version, access, name, signature, superName, interfaces);
    }

    @Override
    public RecordComponentVisitor visitRecordComponent(String name, String descriptor,
                                                       String signature) {
        recordComponents.add(new RecordObjectMethodsMetadata.Component(name, descriptor));
        return super.visitRecordComponent(name, descriptor, signature);
    }

    @Override
    public AnnotationVisitor visitAnnotation(String descriptor, boolean visible) {
        if (isIgnoreAnnotation(descriptor)) ignored = true;
        return super.visitAnnotation(descriptor, visible);
    }

    @Override
    public FieldVisitor visitField(int access, String name, String descriptor,
                                   String signature, Object value) {
        Object emittedValue = value;
        if (!ignored && STRING_DESCRIPTOR.equals(descriptor) && value instanceof String
                && (access & Opcodes.ACC_STATIC) != 0 && (access & Opcodes.ACC_FINAL) != 0) {
            EncryptedString encrypted = context.encrypt((String) value, className,
                    className + "->" + name + ":field");
            if (encrypted != null) {
                staticFields.add(new StaticFieldPlan(name, encrypted));
                emittedValue = null;
            }
        }
        return super.visitField(access, name, descriptor, signature, emittedValue);
    }

    @Override
    public MethodVisitor visitMethod(int access, String name, String descriptor,
                                     String signature, String[] exceptions) {
        MethodVisitor delegate = super.visitMethod(access, name, descriptor, signature, exceptions);
        if (delegate == null || ignored) return delegate;
        if ("<clinit>".equals(name)) hasClassInitializer = true;
        return new BufferedMethodNode(access, name, descriptor, signature, exceptions,
                delegate, "<clinit>".equals(name));
    }

    @Override
    public void visitEnd() {
        if (!ignored && !hasClassInitializer && !staticFields.isEmpty()) {
            MethodVisitor delegate = super.visitMethod(Opcodes.ACC_STATIC, "<clinit>", "()V",
                    null, null);
            MethodNode original = new MethodNode(Opcodes.ASM9, Opcodes.ACC_STATIC,
                    "<clinit>", "()V", null, null);
            original.visitCode();
            original.visitInsn(Opcodes.RETURN);
            original.visitMaxs(0, 0);
            original.visitEnd();
            emitBufferedMethod(original, delegate, "<clinit>", "()V", true);
        }
        super.visitEnd();
    }

    private void emitStaticFieldInitializers(MethodVisitor method, Carrier carrier) {
        for (StaticFieldPlan field : staticFields) {
            String location = className + "->" + field.name + ":field";
            emitEncrypted(method, field.value, location, carrier);
            method.visitFieldInsn(Opcodes.PUTSTATIC, className, field.name, STRING_DESCRIPTOR);
        }
    }

    private void emitEncrypted(MethodVisitor method, EncryptedString encrypted,
                               String location, Carrier carrier) {
        if (carrier == Carrier.BYTES) {
            emitByteCarrier(method, encrypted);
            return;
        }
        emitBase64Carrier(method, createBase64Carrier(encrypted, location));
    }

    private void emitByteCarrier(MethodVisitor method, EncryptedString encrypted) {
        emitByteArray(method, encrypted.value);
        emitByteArray(method, encrypted.key);
        method.visitMethodInsn(Opcodes.INVOKESTATIC, context.getBridgeInternalName(), "decrypt",
                "([B[B)Ljava/lang/String;", false);
    }

    private void emitBase64Carrier(MethodVisitor method, Base64Carrier base64) {
        method.visitLdcInsn(base64.value);
        method.visitLdcInsn(base64.key);
        method.visitMethodInsn(Opcodes.INVOKESTATIC, context.getBridgeInternalName(), "decrypt",
                "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;", false);
    }

    private static Base64Carrier createBase64Carrier(EncryptedString encrypted, String location) {
        requireBase64ConstantUtf8(encrypted.value, "ciphertext", location);
        requireBase64ConstantUtf8(encrypted.key, "key", location);
        String value = Base64.getEncoder().encodeToString(encrypted.value);
        String key = Base64.getEncoder().encodeToString(encrypted.key);
        requireConstantUtf8(value, "ciphertext", location);
        requireConstantUtf8(key, "key", location);
        return new Base64Carrier(value, key);
    }

    private static void requireBase64ConstantUtf8(byte[] value, String kind, String location) {
        long encodedBytes = (((long) value.length + 2L) / 3L) * 4L;
        if (encodedBytes > 65_535L) {
            throw constantUtf8Exceeded(kind, location, encodedBytes);
        }
    }

    private static void requireConstantUtf8(String value, String kind, String location) {
        long encodedBytes = modifiedUtf8Length(value);
        if (encodedBytes > 65_535L) {
            throw constantUtf8Exceeded(kind, location, encodedBytes);
        }
    }

    private static IllegalStateException constantUtf8Exceeded(String kind, String location,
                                                               long encodedBytes) {
        return new IllegalStateException("string encryption BASE64 " + kind
                + " exceeds JVM CONSTANT_Utf8 limit at " + location
                + ": encodedBytes=" + encodedBytes + ", limit=65535");
    }

    /** JVMS 4.4.7 modified UTF-8 length (supplementary chars are encoded as surrogate pairs). */
    private static long modifiedUtf8Length(String value) {
        long length = 0L;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c >= 0x0001 && c <= 0x007f) length++;
            else if (c <= 0x07ff) length += 2L;
            else length += 3L;
        }
        return length;
    }

    private static void emitByteArray(MethodVisitor method, byte[] value) {
        pushInt(method, value.length);
        method.visitIntInsn(Opcodes.NEWARRAY, Opcodes.T_BYTE);
        for (int i = 0; i < value.length; i++) {
            method.visitInsn(Opcodes.DUP);
            pushInt(method, i);
            pushInt(method, value[i]);
            method.visitInsn(Opcodes.BASTORE);
        }
    }

    private static void pushInt(MethodVisitor method, int value) {
        if (value >= -1 && value <= 5) {
            method.visitInsn(Opcodes.ICONST_0 + value);
        } else if (value >= Byte.MIN_VALUE && value <= Byte.MAX_VALUE) {
            method.visitIntInsn(Opcodes.BIPUSH, value);
        } else if (value >= Short.MIN_VALUE && value <= Short.MAX_VALUE) {
            method.visitIntInsn(Opcodes.SIPUSH, value);
        } else {
            method.visitLdcInsn(value);
        }
    }

    private static boolean isIgnoreAnnotation(String descriptor) {
        return IGNORE_ANNOTATION.equals(descriptor) || LEGACY_IGNORE_ANNOTATION.equals(descriptor)
                || (descriptor != null && descriptor.endsWith("/StringEncryptionIgnore;"));
    }

    private static boolean hasNonWhitespaceText(String value) {
        return value != null && !value.trim().isEmpty();
    }

    /** StringConcatFactory reserves U+0001/U+0002 as dynamic/static argument placeholders. */
    private static boolean concatRecipeHasLiteralText(String recipe) {
        if (recipe == null || recipe.isEmpty()) return false;
        StringBuilder literal = new StringBuilder(recipe.length());
        for (int i = 0; i < recipe.length(); i++) {
            char value = recipe.charAt(i);
            if (value != 1 && value != 2) literal.append(value);
        }
        return hasNonWhitespaceText(literal.toString());
    }

    private void emitBufferedMethod(MethodNode original, MethodVisitor delegate,
                                    String methodName, String methodDescriptor,
                                    boolean classInitializer) {
        String methodId = className + "->" + methodName + methodDescriptor;
        MethodEncryptionPlan plan = collectMethodPlan(original, methodName, methodDescriptor,
                classInitializer);
        if (plan.encryptedConstantCount() == 0) {
            original.accept(delegate);
            return;
        }
        int originalMaxCodeBytes = maxCodeSize(original);
        Carrier carrier;
        int plannedMaxCodeBytes;
        if (context.getMode() == StringEncryptionMode.BYTES) {
            int byteMaxCodeBytes = evaluateMethod(original, plan, Carrier.BYTES);
            if (byteMaxCodeBytes <= MAX_JVM_CODE_BYTES) {
                carrier = Carrier.BYTES;
                plannedMaxCodeBytes = byteMaxCodeBytes;
            } else {
                carrier = Carrier.BASE64;
                plannedMaxCodeBytes = evaluateMethod(original, plan, Carrier.BASE64);
                LOGGER.lifecycle("[dex-cfg-obf] string carrier fallback to BASE64 for {} "
                                + "(bytesMaxCodeBytesEstimate={}, "
                                + "base64MaxCodeBytesEstimate={})",
                        methodId, byteMaxCodeBytes, plannedMaxCodeBytes);
            }
        } else {
            carrier = Carrier.BASE64;
            plannedMaxCodeBytes = evaluateMethod(original, plan, Carrier.BASE64);
        }
        if (plannedMaxCodeBytes > MAX_JVM_CODE_BYTES) {
            throw methodPlanExceeded(methodId, originalMaxCodeBytes, plannedMaxCodeBytes,
                    carrier, plan.encryptedConstantCount());
        }
        MethodNode transformed = renderMethod(original, plan, carrier);
        int transformedMaxCodeBytes = maxCodeSize(transformed);
        if (transformedMaxCodeBytes != plannedMaxCodeBytes) {
            throw new IllegalStateException("internal string encryption method-size plan mismatch in "
                    + methodId + ": plannedMaxCodeBytesEstimate=" + plannedMaxCodeBytes
                    + ", transformedMaxCodeBytesEstimate=" + transformedMaxCodeBytes
                    + ", carrier=" + carrier);
        }
        // R8 may otherwise inline or merge the exact method that owns the encrypted literals,
        // making source-to-final member evidence ambiguous. Class initializers cannot be matched by
        // R8 annotation member rules, so their exact owner is resolved and checked separately.
        if (!classInitializer) {
            AnnotationVisitor marker = transformed.visitAnnotation(
                    context.getMethodMarkerAnnotationDescriptor(), false);
            marker.visitEnd();
        }
        transformed.accept(delegate);
        if (carrier == Carrier.BASE64) {
            context.recordBase64CarrierUsage();
        } else {
            context.recordByteCarrierUsage();
        }
    }

    private MethodEncryptionPlan collectMethodPlan(MethodNode original, String methodName,
                                                   String methodDescriptor,
                                                   boolean classInitializer) {
        MethodPlanCollector collector = new MethodPlanCollector(methodName, methodDescriptor,
                classInitializer);
        original.accept(collector);
        return collector.toPlan();
    }

    private int evaluateMethod(MethodNode original, MethodEncryptionPlan plan, Carrier carrier) {
        CodeSizeEvaluator evaluator = new CodeSizeEvaluator(null);
        original.accept(new PlannedEncryptingMethodVisitor(evaluator, plan, carrier));
        return evaluator.getMaxSize();
    }

    private MethodNode renderMethod(MethodNode original, MethodEncryptionPlan plan,
                                    Carrier carrier) {
        MethodNode transformed = new MethodNode(Opcodes.ASM9, original.access, original.name,
                original.desc, original.signature,
                original.exceptions == null ? null : original.exceptions.toArray(new String[0]));
        original.accept(new PlannedEncryptingMethodVisitor(transformed, plan, carrier));
        return transformed;
    }

    private static int maxCodeSize(MethodNode method) {
        CodeSizeEvaluator evaluator = new CodeSizeEvaluator(null);
        method.accept(evaluator);
        return evaluator.getMaxSize();
    }

    private final class BufferedMethodNode extends MethodNode {
        private final MethodVisitor delegate;
        private final boolean classInitializer;

        BufferedMethodNode(int access, String name, String descriptor, String signature,
                           String[] exceptions, MethodVisitor delegate,
                           boolean classInitializer) {
            super(Opcodes.ASM9, access, name, descriptor, signature, exceptions);
            this.delegate = delegate;
            this.classInitializer = classInitializer;
        }

        @Override
        public void visitEnd() {
            super.visitEnd();
            emitBufferedMethod(this, delegate, name, desc, classInitializer);
        }
    }

    private final class MethodPlanCollector extends MethodVisitor {
        private final String methodName;
        private final String methodDescriptor;
        private final boolean classInitializer;
        private final List<LiteralPlan> literals = new ArrayList<>();
        private int stringOrdinal;
        private int unsupportedOrdinal;
        private boolean methodIgnored;

        MethodPlanCollector(String methodName, String methodDescriptor,
                            boolean classInitializer) {
            super(Opcodes.ASM9);
            this.methodName = methodName;
            this.methodDescriptor = methodDescriptor;
            this.classInitializer = classInitializer;
        }

        @Override
        public AnnotationVisitor visitAnnotation(String descriptor, boolean visible) {
            if (isIgnoreAnnotation(descriptor)) methodIgnored = true;
            return super.visitAnnotation(descriptor, visible);
        }

        @Override
        public void visitLdcInsn(Object value) {
            if (!methodIgnored && value instanceof ConstantDynamic) {
                inspectConstantDynamic((ConstantDynamic) value);
            }
            if (!methodIgnored && value instanceof String) {
                String location = className + "->" + methodName + methodDescriptor
                        + "#" + stringOrdinal++;
                EncryptedString encrypted = context.encrypt((String) value, className, location);
                literals.add(new LiteralPlan((String) value, encrypted, location));
            }
        }

        @Override
        public void visitInvokeDynamicInsn(String name, String descriptor,
                                           Handle bootstrapMethodHandle,
                                           Object... bootstrapMethodArguments) {
            if (!methodIgnored) {
                boolean stringConcat =
                        CompilerCallSiteMetadata.isJavacStringConcatWithConstants(
                                name, descriptor, bootstrapMethodHandle,
                                bootstrapMethodArguments);
                for (int i = 0; i < bootstrapMethodArguments.length; i++) {
                    Object argument = bootstrapMethodArguments[i];
                    if (stringConcat && i == 0 && argument instanceof String) {
                        if (concatRecipeHasLiteralText((String) argument)) {
                            recordUnsupported("StringConcatFactory recipe");
                        }
                    } else if (RecordObjectMethodsMetadata.isStructuralComponentNames(
                            recordClass, className, recordComponents, methodName,
                            methodDescriptor, name, descriptor, bootstrapMethodHandle,
                            bootstrapMethodArguments, i)) {
                        // javac stores the semicolon-delimited record component names here.
                        // ObjectMethods consumes them as structural metadata; they are not an
                        // executable application String and cannot be replaced with a decrypt call.
                    } else {
                        inspectInvokeDynamicBootstrapArgument(argument, stringConcat);
                    }
                }
                if (name != null && !name.isEmpty()
                        && !CompilerCallSiteMetadata.isStructuralInvokeDynamicName(
                        recordClass, className, recordComponents, methodName,
                        methodDescriptor, name, descriptor, bootstrapMethodHandle,
                        bootstrapMethodArguments)) {
                    recordUnsupported("invokedynamic name");
                }
            }
        }

        private void inspectInvokeDynamicBootstrapArgument(Object argument,
                                                           boolean stringConcat) {
            if (argument instanceof String && hasNonWhitespaceText((String) argument)) {
                recordUnsupported(stringConcat ? "StringConcatFactory bootstrap String"
                        : "invokedynamic bootstrap String");
            } else if (argument instanceof ConstantDynamic) {
                inspectConstantDynamic((ConstantDynamic) argument);
            }
        }

        private void inspectConstantDynamic(ConstantDynamic dynamic) {
            CompilerCallSiteMetadata.scanConstantDynamic(dynamic,
                    value -> {
                        if (hasNonWhitespaceText(value)) {
                            recordUnsupported("ConstantDynamic bootstrap String");
                        }
                    },
                    name -> {
                        if (name != null && !name.isEmpty()) {
                            recordUnsupported("ConstantDynamic name");
                        }
                    });
        }

        private void recordUnsupported(String kind) {
            String location = className + "->" + methodName + methodDescriptor
                    + "#unsupported-" + unsupportedOrdinal++;
            context.recordUnsupportedStringConstant(kind, location);
        }

        MethodEncryptionPlan toPlan() {
            return new MethodEncryptionPlan(classInitializer, methodIgnored,
                    classInitializer ? staticFields.size() : 0, literals);
        }
    }

    private final class PlannedEncryptingMethodVisitor extends MethodVisitor {
        private final MethodEncryptionPlan plan;
        private final Carrier carrier;
        private int literalIndex;

        PlannedEncryptingMethodVisitor(MethodVisitor delegate, MethodEncryptionPlan plan,
                                       Carrier carrier) {
            super(Opcodes.ASM9, delegate);
            this.plan = plan;
            this.carrier = carrier;
        }

        @Override
        public void visitCode() {
            super.visitCode();
            if (plan.classInitializer) emitStaticFieldInitializers(mv, carrier);
        }

        @Override
        public void visitLdcInsn(Object value) {
            if (!plan.methodIgnored && value instanceof String) {
                if (literalIndex >= plan.literals.size()) {
                    throw new IllegalStateException("internal string encryption plan underflow in "
                            + className);
                }
                LiteralPlan literal = plan.literals.get(literalIndex++);
                if (!literal.originalValue.equals(value)) {
                    throw new IllegalStateException("internal string encryption plan mismatch in "
                            + className);
                }
                if (literal.encrypted != null) {
                    emitEncrypted(mv, literal.encrypted, literal.location, carrier);
                    return;
                }
            }
            super.visitLdcInsn(value);
        }

        @Override
        public void visitEnd() {
            if (literalIndex != plan.literals.size()) {
                throw new IllegalStateException("internal string encryption plan overflow in "
                        + className + ": planned=" + plan.literals.size()
                        + ", consumed=" + literalIndex);
            }
            super.visitEnd();
        }
    }

    private static IllegalStateException methodPlanExceeded(String methodId,
                                                            int originalMaxCodeBytes,
                                                            int plannedMaxCodeBytes,
                                                            Carrier carrier,
                                                            int encryptedConstants) {
        int requiredAdditionalBytes = plannedMaxCodeBytes - originalMaxCodeBytes;
        int excessBytes = plannedMaxCodeBytes - MAX_JVM_CODE_BYTES;
        return new IllegalStateException("string encryption method-wide " + carrier
                + " carrier plan conservative max estimate would exceed JVM Code attribute "
                + "limit in " + methodId
                + ": originalMaxCodeBytesEstimate=" + originalMaxCodeBytes
                + ", plannedMaxCodeBytesEstimate=" + plannedMaxCodeBytes
                + ", requiredAdditionalBytesEstimate=" + requiredAdditionalBytes
                + ", excessBytesEstimate=" + excessBytes
                + ", encryptedConstants=" + encryptedConstants
                + ", carrier=" + carrier + ", limit=" + MAX_JVM_CODE_BYTES);
    }

    private enum Carrier {
        BYTES,
        BASE64
    }

    private static final class MethodEncryptionPlan {
        final boolean classInitializer;
        final boolean methodIgnored;
        final int injectedStaticFieldCount;
        final List<LiteralPlan> literals;

        MethodEncryptionPlan(boolean classInitializer, boolean methodIgnored,
                             int injectedStaticFieldCount,
                             List<LiteralPlan> literals) {
            this.classInitializer = classInitializer;
            this.methodIgnored = methodIgnored;
            this.injectedStaticFieldCount = injectedStaticFieldCount;
            this.literals = new ArrayList<>(literals);
        }

        int encryptedConstantCount() {
            int count = injectedStaticFieldCount;
            for (LiteralPlan literal : literals) {
                if (literal.encrypted != null) count++;
            }
            return count;
        }
    }

    private static final class LiteralPlan {
        final String originalValue;
        final EncryptedString encrypted;
        final String location;

        LiteralPlan(String originalValue, EncryptedString encrypted, String location) {
            this.originalValue = originalValue;
            this.encrypted = encrypted;
            this.location = location;
        }
    }

    private static final class StaticFieldPlan {
        final String name;
        final EncryptedString value;

        StaticFieldPlan(String name, EncryptedString value) {
            this.name = name;
            this.value = value;
        }
    }

    private static final class Base64Carrier {
        final String value;
        final String key;

        Base64Carrier(String value, String key) {
            this.value = value;
            this.key = key;
        }
    }
}
