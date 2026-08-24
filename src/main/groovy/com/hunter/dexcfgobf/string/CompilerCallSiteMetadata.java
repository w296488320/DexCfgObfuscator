package com.hunter.dexcfgobf.string;

import com.android.tools.smali.dexlib2.MethodHandleType;
import com.android.tools.smali.dexlib2.iface.Method;
import com.android.tools.smali.dexlib2.iface.reference.CallSiteReference;
import com.android.tools.smali.dexlib2.iface.reference.FieldReference;
import com.android.tools.smali.dexlib2.iface.reference.MethodHandleReference;
import com.android.tools.smali.dexlib2.iface.reference.MethodProtoReference;
import com.android.tools.smali.dexlib2.iface.reference.MethodReference;
import com.android.tools.smali.dexlib2.iface.reference.Reference;
import com.android.tools.smali.dexlib2.iface.value.EncodedValue;
import com.android.tools.smali.dexlib2.iface.value.IntEncodedValue;
import com.android.tools.smali.dexlib2.iface.value.MethodHandleEncodedValue;
import com.android.tools.smali.dexlib2.iface.value.MethodTypeEncodedValue;
import com.android.tools.smali.dexlib2.iface.value.StringEncodedValue;
import com.android.tools.smali.dexlib2.iface.value.TypeEncodedValue;

import org.objectweb.asm.ConstantDynamic;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;

import java.util.ArrayDeque;
import java.util.Collections;
import java.util.Deque;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Set;
import java.util.function.Consumer;

/**
 * Conservative recognizers for names that a Java compiler stores in a dynamic call site as
 * linkage metadata. A bootstrap owner/name match alone is intentionally never sufficient: an
 * unknown or malformed shape must keep its name in the runtime-payload gate.
 */
final class CompilerCallSiteMetadata {
    private static final String STRING_CONCAT_FACTORY =
            "java/lang/invoke/StringConcatFactory";
    private static final String STRING_CONCAT_FACTORY_DEX =
            "Ljava/lang/invoke/StringConcatFactory;";
    private static final String MAKE_CONCAT = "makeConcat";
    private static final String MAKE_CONCAT_WITH_CONSTANTS = "makeConcatWithConstants";
    private static final String MAKE_CONCAT_DESCRIPTOR =
            "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;"
                    + "Ljava/lang/invoke/MethodType;)Ljava/lang/invoke/CallSite;";
    private static final String MAKE_CONCAT_WITH_CONSTANTS_DESCRIPTOR =
            "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;"
                    + "Ljava/lang/invoke/MethodType;Ljava/lang/String;[Ljava/lang/Object;)"
                    + "Ljava/lang/invoke/CallSite;";

    private static final String LAMBDA_METAFACTORY =
            "java/lang/invoke/LambdaMetafactory";
    private static final String LAMBDA_METAFACTORY_DEX =
            "Ljava/lang/invoke/LambdaMetafactory;";
    private static final String METAFACTORY = "metafactory";
    private static final String ALT_METAFACTORY = "altMetafactory";
    private static final String METAFACTORY_DESCRIPTOR =
            "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;"
                    + "Ljava/lang/invoke/MethodType;Ljava/lang/invoke/MethodType;"
                    + "Ljava/lang/invoke/MethodHandle;Ljava/lang/invoke/MethodType;)"
                    + "Ljava/lang/invoke/CallSite;";
    private static final String ALT_METAFACTORY_DESCRIPTOR =
            "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;"
                    + "Ljava/lang/invoke/MethodType;[Ljava/lang/Object;)"
                    + "Ljava/lang/invoke/CallSite;";
    private static final int FLAG_SERIALIZABLE = 1;
    private static final int FLAG_MARKERS = 2;
    private static final int FLAG_BRIDGES = 4;
    private static final int KNOWN_ALT_METAFACTORY_FLAGS =
            FLAG_SERIALIZABLE | FLAG_MARKERS | FLAG_BRIDGES;

    private static final String OBJECT_METHODS_DEX = "Ljava/lang/runtime/ObjectMethods;";
    private static final String OBJECT_METHODS_BOOTSTRAP = "bootstrap";
    private static final String OBJECT_METHODS_BOOTSTRAP_RETURN = "Ljava/lang/Object;";
    private static final String[] OBJECT_METHODS_BOOTSTRAP_PARAMETERS = {
            "Ljava/lang/invoke/MethodHandles$Lookup;",
            "Ljava/lang/String;",
            "Ljava/lang/invoke/TypeDescriptor;",
            "Ljava/lang/Class;",
            "Ljava/lang/String;",
            "[Ljava/lang/invoke/MethodHandle;"
    };

    private CompilerCallSiteMetadata() {
    }

    /**
     * Visits every String bootstrap argument and every name in a ConstantDynamic graph without
     * using the Java call stack. Identity tracking makes malformed cyclic/shared graphs finite.
     * Bootstrap arguments retain their depth-first order and are visited before the owning name.
     */
    static void scanConstantDynamic(ConstantDynamic root,
                                    Consumer<String> bootstrapStringConsumer,
                                    Consumer<String> nameConsumer) {
        if (root == null) return;
        Set<ConstantDynamic> seen = Collections.newSetFromMap(new IdentityHashMap<>());
        Deque<Object> pending = new ArrayDeque<>();
        pending.push(root);
        while (!pending.isEmpty()) {
            Object value = pending.pop();
            if (value instanceof PendingConstantDynamicName) {
                nameConsumer.accept(((PendingConstantDynamicName) value).dynamic.getName());
                continue;
            }
            if (value instanceof String) {
                bootstrapStringConsumer.accept((String) value);
                continue;
            }
            ConstantDynamic dynamic = (ConstantDynamic) value;
            if (!seen.add(dynamic)) continue;
            pending.push(new PendingConstantDynamicName(dynamic));
            for (int i = dynamic.getBootstrapMethodArgumentCount() - 1; i >= 0; i--) {
                Object argument = dynamic.getBootstrapMethodArgument(i);
                if (argument instanceof String || argument instanceof ConstantDynamic) {
                    pending.push(argument);
                }
            }
        }
    }

    static boolean isJavacStringConcatWithConstants(String invokeDynamicName,
                                                     String invokeDynamicDescriptor,
                                                     Handle bootstrapMethodHandle,
                                                     Object[] bootstrapMethodArguments) {
        if (!exactAsmBootstrap(bootstrapMethodHandle, STRING_CONCAT_FACTORY,
                MAKE_CONCAT_WITH_CONSTANTS, MAKE_CONCAT_WITH_CONSTANTS_DESCRIPTOR)
                || !MAKE_CONCAT_WITH_CONSTANTS.equals(invokeDynamicName)
                || !returnsString(invokeDynamicDescriptor)
                || bootstrapMethodArguments == null
                || bootstrapMethodArguments.length == 0
                || !(bootstrapMethodArguments[0] instanceof String)) {
            return false;
        }
        String recipe = (String) bootstrapMethodArguments[0];
        int dynamicArguments = 0;
        int staticArguments = 0;
        for (int i = 0; i < recipe.length(); i++) {
            char value = recipe.charAt(i);
            if (value == 1) dynamicArguments++;
            else if (value == 2) staticArguments++;
        }
        try {
            return dynamicArguments == Type.getArgumentTypes(invokeDynamicDescriptor).length
                    && staticArguments == bootstrapMethodArguments.length - 1;
        } catch (IllegalArgumentException malformedDescriptor) {
            return false;
        }
    }

    static boolean isStructuralInvokeDynamicName(boolean recordClass,
                                                 String className,
                                                 List<RecordObjectMethodsMetadata.Component>
                                                         recordComponents,
                                                 String enclosingMethodName,
                                                 String enclosingMethodDescriptor,
                                                 String invokeDynamicName,
                                                 String invokeDynamicDescriptor,
                                                 Handle bootstrapMethodHandle,
                                                 Object[] bootstrapMethodArguments) {
        if (isJavacStringConcatWithConstants(invokeDynamicName, invokeDynamicDescriptor,
                bootstrapMethodHandle, bootstrapMethodArguments)
                || isJavacStringConcat(invokeDynamicName, invokeDynamicDescriptor,
                bootstrapMethodHandle, bootstrapMethodArguments)
                || isJavacLambda(invokeDynamicName, invokeDynamicDescriptor,
                bootstrapMethodHandle, bootstrapMethodArguments)) {
            return true;
        }
        return RecordObjectMethodsMetadata.isStructuralComponentNames(
                recordClass, className, recordComponents, enclosingMethodName,
                enclosingMethodDescriptor, invokeDynamicName, invokeDynamicDescriptor,
                bootstrapMethodHandle, bootstrapMethodArguments, 1);
    }

    private static boolean isJavacStringConcat(String invokeDynamicName,
                                               String invokeDynamicDescriptor,
                                               Handle bootstrapMethodHandle,
                                               Object[] bootstrapMethodArguments) {
        return exactAsmBootstrap(bootstrapMethodHandle, STRING_CONCAT_FACTORY, MAKE_CONCAT,
                MAKE_CONCAT_DESCRIPTOR)
                && MAKE_CONCAT.equals(invokeDynamicName)
                && returnsString(invokeDynamicDescriptor)
                && bootstrapMethodArguments != null
                && bootstrapMethodArguments.length == 0;
    }

    private static boolean isJavacLambda(String invokeDynamicName,
                                         String invokeDynamicDescriptor,
                                         Handle bootstrapMethodHandle,
                                         Object[] bootstrapMethodArguments) {
        if (!isUnqualifiedMethodName(invokeDynamicName)
                || !returnsReference(invokeDynamicDescriptor)
                || bootstrapMethodArguments == null) {
            return false;
        }
        if (exactAsmBootstrap(bootstrapMethodHandle, LAMBDA_METAFACTORY, METAFACTORY,
                METAFACTORY_DESCRIPTOR)) {
            return bootstrapMethodArguments.length == 3
                    && isAsmMethodType(bootstrapMethodArguments[0])
                    && isAsmMethodHandle(bootstrapMethodArguments[1])
                    && isAsmMethodType(bootstrapMethodArguments[2]);
        }
        if (!exactAsmBootstrap(bootstrapMethodHandle, LAMBDA_METAFACTORY, ALT_METAFACTORY,
                ALT_METAFACTORY_DESCRIPTOR)
                || bootstrapMethodArguments.length < 4
                || !isAsmMethodType(bootstrapMethodArguments[0])
                || !isAsmMethodHandle(bootstrapMethodArguments[1])
                || !isAsmMethodType(bootstrapMethodArguments[2])
                || !(bootstrapMethodArguments[3] instanceof Integer)) {
            return false;
        }
        int flags = (Integer) bootstrapMethodArguments[3];
        if (flags < 0 || (flags & ~KNOWN_ALT_METAFACTORY_FLAGS) != 0) return false;
        int index = 4;
        if ((flags & FLAG_MARKERS) != 0) {
            index = consumeAsmTypes(bootstrapMethodArguments, index, false);
            if (index < 0) return false;
        }
        if ((flags & FLAG_BRIDGES) != 0) {
            index = consumeAsmTypes(bootstrapMethodArguments, index, true);
            if (index < 0) return false;
        }
        return index == bootstrapMethodArguments.length;
    }

    private static int consumeAsmTypes(Object[] arguments, int index, boolean methodTypes) {
        if (index >= arguments.length || !(arguments[index] instanceof Integer)) return -1;
        int count = (Integer) arguments[index++];
        if (count < 0 || count > arguments.length - index) return -1;
        for (int i = 0; i < count; i++) {
            Object value = arguments[index++];
            if (!(value instanceof Type)) return -1;
            int sort = ((Type) value).getSort();
            if (methodTypes ? sort != Type.METHOD : sort != Type.OBJECT) return -1;
        }
        return index;
    }

    private static boolean isAsmMethodType(Object value) {
        return value instanceof Type && ((Type) value).getSort() == Type.METHOD;
    }

    private static boolean isAsmMethodHandle(Object value) {
        if (!(value instanceof Handle)) return false;
        Handle handle = (Handle) value;
        if (handle.getTag() < Opcodes.H_INVOKEVIRTUAL
                || handle.getTag() > Opcodes.H_INVOKEINTERFACE) {
            return false;
        }
        try {
            Type.getMethodType(handle.getDesc());
            return true;
        } catch (IllegalArgumentException malformedDescriptor) {
            return false;
        }
    }

    private static boolean exactAsmBootstrap(Handle handle, String owner, String name,
                                             String descriptor) {
        return handle != null
                && handle.getTag() == Opcodes.H_INVOKESTATIC
                && !handle.isInterface()
                && owner.equals(handle.getOwner())
                && name.equals(handle.getName())
                && descriptor.equals(handle.getDesc());
    }

    private static boolean returnsString(String descriptor) {
        try {
            return Type.getType(String.class).equals(Type.getReturnType(descriptor));
        } catch (IllegalArgumentException malformedDescriptor) {
            return false;
        }
    }

    private static boolean returnsReference(String descriptor) {
        try {
            return Type.getReturnType(descriptor).getSort() == Type.OBJECT;
        } catch (IllegalArgumentException malformedDescriptor) {
            return false;
        }
    }

    private static boolean isUnqualifiedMethodName(String value) {
        if (value == null || value.isEmpty() || "<init>".equals(value)
                || "<clinit>".equals(value)) {
            return false;
        }
        for (int i = 0; i < value.length(); i++) {
            switch (value.charAt(i)) {
                case '.':
                case ';':
                case '[':
                case '/':
                case '<':
                case '>':
                    return false;
                default:
                    break;
            }
        }
        return true;
    }

    static boolean isStructuralDexCallSiteName(String ownerType, Method enclosingMethod,
                                               CallSiteReference callSite) {
        if (callSite == null || enclosingMethod == null) return false;
        return isDexStringConcat(callSite)
                || isDexLambda(callSite)
                || isDexRecordObjectMethod(ownerType, enclosingMethod, callSite);
    }

    private static boolean isDexStringConcat(CallSiteReference callSite) {
        MethodReference bootstrap = exactDexBootstrap(callSite.getMethodHandle());
        if (bootstrap == null || !STRING_CONCAT_FACTORY_DEX.equals(
                bootstrap.getDefiningClass())) {
            return false;
        }
        if (MAKE_CONCAT.equals(bootstrap.getName())) {
            return MAKE_CONCAT.equals(callSite.getMethodName())
                    && exactDexMethod(bootstrap, MAKE_CONCAT_DESCRIPTOR)
                    && "Ljava/lang/String;".equals(callSite.getMethodProto().getReturnType())
                    && callSite.getExtraArguments().isEmpty();
        }
        if (!MAKE_CONCAT_WITH_CONSTANTS.equals(bootstrap.getName())
                || !MAKE_CONCAT_WITH_CONSTANTS.equals(callSite.getMethodName())
                || !exactDexMethod(bootstrap, MAKE_CONCAT_WITH_CONSTANTS_DESCRIPTOR)
                || !"Ljava/lang/String;".equals(callSite.getMethodProto().getReturnType())) {
            return false;
        }
        List<? extends EncodedValue> extras = callSite.getExtraArguments();
        if (extras.isEmpty() || !(extras.get(0) instanceof StringEncodedValue)) return false;
        String recipe = ((StringEncodedValue) extras.get(0)).getValue();
        int dynamicArguments = 0;
        int staticArguments = 0;
        for (int i = 0; i < recipe.length(); i++) {
            char value = recipe.charAt(i);
            if (value == 1) dynamicArguments++;
            else if (value == 2) staticArguments++;
        }
        return dynamicArguments == callSite.getMethodProto().getParameterTypes().size()
                && staticArguments == extras.size() - 1;
    }

    private static boolean isDexLambda(CallSiteReference callSite) {
        if (!isUnqualifiedMethodName(callSite.getMethodName())
                || !isObjectType(callSite.getMethodProto().getReturnType())) {
            return false;
        }
        MethodReference bootstrap = exactDexBootstrap(callSite.getMethodHandle());
        if (bootstrap == null || !LAMBDA_METAFACTORY_DEX.equals(
                bootstrap.getDefiningClass())) {
            return false;
        }
        List<? extends EncodedValue> extras = callSite.getExtraArguments();
        if (METAFACTORY.equals(bootstrap.getName())) {
            return exactDexMethod(bootstrap, METAFACTORY_DESCRIPTOR)
                    && extras.size() == 3
                    && extras.get(0) instanceof MethodTypeEncodedValue
                    && isDexMethodHandle(extras.get(1))
                    && extras.get(2) instanceof MethodTypeEncodedValue;
        }
        if (!ALT_METAFACTORY.equals(bootstrap.getName())
                || !exactDexMethod(bootstrap, ALT_METAFACTORY_DESCRIPTOR)
                || extras.size() < 4
                || !(extras.get(0) instanceof MethodTypeEncodedValue)
                || !isDexMethodHandle(extras.get(1))
                || !(extras.get(2) instanceof MethodTypeEncodedValue)
                || !(extras.get(3) instanceof IntEncodedValue)) {
            return false;
        }
        int flags = ((IntEncodedValue) extras.get(3)).getValue();
        if (flags < 0 || (flags & ~KNOWN_ALT_METAFACTORY_FLAGS) != 0) return false;
        int index = 4;
        if ((flags & FLAG_MARKERS) != 0) {
            index = consumeDexValues(extras, index, false);
            if (index < 0) return false;
        }
        if ((flags & FLAG_BRIDGES) != 0) {
            index = consumeDexValues(extras, index, true);
            if (index < 0) return false;
        }
        return index == extras.size();
    }

    private static int consumeDexValues(List<? extends EncodedValue> extras, int index,
                                        boolean methodTypes) {
        if (index >= extras.size() || !(extras.get(index) instanceof IntEncodedValue)) return -1;
        int count = ((IntEncodedValue) extras.get(index++)).getValue();
        if (count < 0 || count > extras.size() - index) return -1;
        for (int i = 0; i < count; i++) {
            EncodedValue value = extras.get(index++);
            if (methodTypes ? !(value instanceof MethodTypeEncodedValue)
                    : !(value instanceof TypeEncodedValue)
                    || !isObjectType(((TypeEncodedValue) value).getValue())) {
                return -1;
            }
        }
        return index;
    }

    private static boolean isDexMethodHandle(EncodedValue value) {
        if (!(value instanceof MethodHandleEncodedValue)) return false;
        MethodHandleReference handle = ((MethodHandleEncodedValue) value).getValue();
        int kind = handle.getMethodHandleType();
        return kind >= MethodHandleType.INVOKE_STATIC
                && kind <= MethodHandleType.INVOKE_INTERFACE
                && handle.getMemberReference() instanceof MethodReference;
    }

    private static boolean isDexRecordObjectMethod(String ownerType, Method enclosingMethod,
                                                   CallSiteReference callSite) {
        if (ownerType == null || !ownerType.equals(enclosingMethod.getDefiningClass())
                || (enclosingMethod.getAccessFlags() & Opcodes.ACC_STATIC) != 0) {
            return false;
        }
        String name = callSite.getMethodName();
        MethodProtoReference proto = callSite.getMethodProto();
        if (!name.equals(enclosingMethod.getName())
                || !isGeneratedRecordMethodShape(ownerType, name,
                enclosingMethod.getParameterTypes(), enclosingMethod.getReturnType(), proto)) {
            return false;
        }
        MethodReference bootstrap = exactDexBootstrap(callSite.getMethodHandle());
        if (bootstrap == null || !OBJECT_METHODS_DEX.equals(bootstrap.getDefiningClass())
                || !OBJECT_METHODS_BOOTSTRAP.equals(bootstrap.getName())
                || !exactDexMethod(bootstrap, OBJECT_METHODS_BOOTSTRAP_PARAMETERS,
                OBJECT_METHODS_BOOTSTRAP_RETURN)) {
            return false;
        }
        List<? extends EncodedValue> extras = callSite.getExtraArguments();
        if (extras.size() < 2 || !(extras.get(0) instanceof TypeEncodedValue)
                || !ownerType.equals(((TypeEncodedValue) extras.get(0)).getValue())
                || !(extras.get(1) instanceof StringEncodedValue)
                || extras.size() - 2 != countComponentNames(
                ((StringEncodedValue) extras.get(1)).getValue())) {
            return false;
        }
        StringBuilder componentNames = new StringBuilder();
        for (int i = 2; i < extras.size(); i++) {
            EncodedValue value = extras.get(i);
            if (!(value instanceof MethodHandleEncodedValue)) return false;
            MethodHandleReference handle = ((MethodHandleEncodedValue) value).getValue();
            Reference member = handle.getMemberReference();
            if (handle.getMethodHandleType() != MethodHandleType.INSTANCE_GET
                    || !(member instanceof FieldReference)) {
                return false;
            }
            FieldReference field = (FieldReference) member;
            if (!ownerType.equals(field.getDefiningClass())) return false;
            if (componentNames.length() != 0) componentNames.append(';');
            componentNames.append(field.getName());
        }
        return componentNames.toString().equals(
                ((StringEncodedValue) extras.get(1)).getValue());
    }

    private static boolean isGeneratedRecordMethodShape(
            String ownerType, String name, List<? extends CharSequence> enclosingParameters,
            String enclosingReturn, MethodProtoReference callSiteProto) {
        List<? extends CharSequence> callParameters = callSiteProto.getParameterTypes();
        if ("toString".equals(name)) {
            return enclosingParameters.isEmpty()
                    && "Ljava/lang/String;".equals(enclosingReturn)
                    && callParameters.size() == 1
                    && ownerType.contentEquals(callParameters.get(0))
                    && "Ljava/lang/String;".equals(callSiteProto.getReturnType());
        }
        if ("hashCode".equals(name)) {
            return enclosingParameters.isEmpty() && "I".equals(enclosingReturn)
                    && callParameters.size() == 1
                    && ownerType.contentEquals(callParameters.get(0))
                    && "I".equals(callSiteProto.getReturnType());
        }
        return "equals".equals(name)
                && enclosingParameters.size() == 1
                && "Ljava/lang/Object;".contentEquals(enclosingParameters.get(0))
                && "Z".equals(enclosingReturn)
                && callParameters.size() == 2
                && ownerType.contentEquals(callParameters.get(0))
                && "Ljava/lang/Object;".contentEquals(callParameters.get(1))
                && "Z".equals(callSiteProto.getReturnType());
    }

    private static int countComponentNames(String names) {
        if (names == null || names.isEmpty()) return 0;
        int count = 1;
        for (int i = 0; i < names.length(); i++) {
            if (names.charAt(i) == ';') count++;
        }
        return count;
    }

    private static MethodReference exactDexBootstrap(MethodHandleReference handle) {
        if (handle == null || handle.getMethodHandleType() != MethodHandleType.INVOKE_STATIC
                || !(handle.getMemberReference() instanceof MethodReference)) {
            return null;
        }
        return (MethodReference) handle.getMemberReference();
    }

    private static boolean exactDexMethod(MethodReference method, String asmDescriptor) {
        try {
            Type type = Type.getMethodType(asmDescriptor);
            Type[] parameters = type.getArgumentTypes();
            if (parameters.length != method.getParameterTypes().size()
                    || !type.getReturnType().getDescriptor().equals(method.getReturnType())) {
                return false;
            }
            for (int i = 0; i < parameters.length; i++) {
                if (!parameters[i].getDescriptor().contentEquals(
                        method.getParameterTypes().get(i))) {
                    return false;
                }
            }
            return true;
        } catch (IllegalArgumentException malformedDescriptor) {
            return false;
        }
    }

    private static boolean exactDexMethod(MethodReference method, String[] parameters,
                                          String returnType) {
        if (!returnType.equals(method.getReturnType())
                || parameters.length != method.getParameterTypes().size()) {
            return false;
        }
        for (int i = 0; i < parameters.length; i++) {
            if (!parameters[i].contentEquals(method.getParameterTypes().get(i))) return false;
        }
        return true;
    }

    private static boolean isObjectType(String descriptor) {
        return descriptor != null && descriptor.startsWith("L");
    }

    private static final class PendingConstantDynamicName {
        final ConstantDynamic dynamic;

        PendingConstantDynamicName(ConstantDynamic dynamic) {
            this.dynamic = dynamic;
        }
    }
}
