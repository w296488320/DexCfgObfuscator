package com.hunter.dexcfgobf.string;

import org.objectweb.asm.Handle;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;

import java.util.List;

/** Exact classifier for the structural component-name argument emitted by javac records. */
final class RecordObjectMethodsMetadata {
    static final String RECORD_SUPER = "java/lang/Record";
    private static final String OBJECT_METHODS = "java/lang/runtime/ObjectMethods";
    private static final String OBJECT_METHODS_BOOTSTRAP = "bootstrap";
    private static final String OBJECT_METHODS_BOOTSTRAP_DESCRIPTOR =
            "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;"
                    + "Ljava/lang/invoke/TypeDescriptor;Ljava/lang/Class;Ljava/lang/String;"
                    + "[Ljava/lang/invoke/MethodHandle;)Ljava/lang/Object;";

    private RecordObjectMethodsMetadata() {
    }

    static boolean isStructuralComponentNames(boolean recordClass,
                                              String className,
                                              List<Component> components,
                                              String enclosingMethodName,
                                              String enclosingMethodDescriptor,
                                              String invokeDynamicName,
                                              String invokeDynamicDescriptor,
                                              Handle bootstrapMethodHandle,
                                              Object[] bootstrapMethodArguments,
                                              int argumentIndex) {
        if (!recordClass || argumentIndex != 1
                || !isGeneratedRecordObjectMethod(className, enclosingMethodName,
                enclosingMethodDescriptor, invokeDynamicName, invokeDynamicDescriptor)) {
            return false;
        }
        if (bootstrapMethodHandle == null
                || bootstrapMethodHandle.getTag() != Opcodes.H_INVOKESTATIC
                || bootstrapMethodHandle.isInterface()
                || !OBJECT_METHODS.equals(bootstrapMethodHandle.getOwner())
                || !OBJECT_METHODS_BOOTSTRAP.equals(bootstrapMethodHandle.getName())
                || !OBJECT_METHODS_BOOTSTRAP_DESCRIPTOR.equals(
                bootstrapMethodHandle.getDesc())) {
            return false;
        }
        if (bootstrapMethodArguments == null
                || bootstrapMethodArguments.length != components.size() + 2
                || !(bootstrapMethodArguments[0] instanceof Type)
                || !Type.getObjectType(className).equals(bootstrapMethodArguments[0])
                || !(bootstrapMethodArguments[1] instanceof String)
                || !componentNames(components).equals(bootstrapMethodArguments[1])) {
            return false;
        }
        for (int i = 0; i < components.size(); i++) {
            Object argument = bootstrapMethodArguments[i + 2];
            if (!(argument instanceof Handle)) return false;
            Handle field = (Handle) argument;
            Component component = components.get(i);
            if (field.getTag() != Opcodes.H_GETFIELD || field.isInterface()
                    || !className.equals(field.getOwner())
                    || !component.name.equals(field.getName())
                    || !component.descriptor.equals(field.getDesc())) {
                return false;
            }
        }
        return true;
    }

    private static boolean isGeneratedRecordObjectMethod(String className,
                                                           String enclosingMethodName,
                                                           String enclosingMethodDescriptor,
                                                           String invokeDynamicName,
                                                           String invokeDynamicDescriptor) {
        String receiver = "L" + className + ";";
        if ("toString".equals(invokeDynamicName)) {
            return invokeDynamicName.equals(enclosingMethodName)
                    && "()Ljava/lang/String;".equals(enclosingMethodDescriptor)
                    && ("(" + receiver + ")Ljava/lang/String;").equals(
                    invokeDynamicDescriptor);
        }
        if ("hashCode".equals(invokeDynamicName)) {
            return invokeDynamicName.equals(enclosingMethodName)
                    && "()I".equals(enclosingMethodDescriptor)
                    && ("(" + receiver + ")I").equals(invokeDynamicDescriptor);
        }
        return "equals".equals(invokeDynamicName)
                && invokeDynamicName.equals(enclosingMethodName)
                && "(Ljava/lang/Object;)Z".equals(enclosingMethodDescriptor)
                && ("(" + receiver + "Ljava/lang/Object;)Z").equals(
                invokeDynamicDescriptor);
    }

    private static String componentNames(List<Component> components) {
        StringBuilder names = new StringBuilder();
        for (Component component : components) {
            if (names.length() != 0) names.append(';');
            names.append(component.name);
        }
        return names.toString();
    }

    static final class Component {
        final String name;
        final String descriptor;

        Component(String name, String descriptor) {
            this.name = name;
            this.descriptor = descriptor;
        }
    }
}
