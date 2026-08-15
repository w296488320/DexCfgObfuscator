package com.hunter.dexcfgobf;

import com.android.tools.smali.dexlib2.AccessFlags;
import com.android.tools.smali.dexlib2.Opcode;
import com.android.tools.smali.dexlib2.builder.Label;
import com.android.tools.smali.dexlib2.builder.MethodImplementationBuilder;
import com.android.tools.smali.dexlib2.builder.MutableMethodImplementation;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction10x;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction11n;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction21t;
import com.android.tools.smali.dexlib2.iface.Method;
import com.android.tools.smali.dexlib2.iface.MethodImplementation;

import org.junit.Test;

import java.lang.reflect.Proxy;
import java.util.HashSet;
import java.util.Set;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/** 多种确定性 seed 下都必须生成合法体，并覆盖多个 dispatcher/encoder 模板族。 */
public class MultiTemplatePropertyTest {
    @Test
    public void manySeedsProduceMultipleValidTemplates() {
        Set<String> templates = new HashSet<>();
        int smallestOutput = Integer.MAX_VALUE;
        for (long seed = 1; seed <= 128; seed++) {
            ObfuscatorConfig config = new ObfuscatorConfig();
            config.seed = seed;
            config.depth = 2;
            ObfuscatorStats stats = new ObfuscatorStats();
            CfgFlattener flattener = new CfgFlattener(config, ObfuscatorLogger.STDOUT, stats);
            MethodImplementation out = flattener.flatten(method(), sample());
            assertNotNull("seed=" + seed, out);
            MutableMethodImplementation rebuilt = new MutableMethodImplementation(out);
            smallestOutput = Math.min(smallestOutput, rebuilt.getInstructions().size());
            templates.add(flattener.getLastOutcome().template);
        }
        assertTrue("expected packed/sparse and multiple encoders, got " + templates,
                templates.size() >= 14);
        assertTrue("dispatcher/decoy body should materially exceed the 6-instruction source, got "
                + smallestOutput, smallestOutput >= 60);
    }

    private static MethodImplementation sample() {
        MethodImplementationBuilder b = new MethodImplementationBuilder(1);
        Label yes = b.getLabel("Yes");
        b.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 0, 0));
        b.addInstruction(new BuilderInstruction21t(Opcode.IF_EQZ, 0, yes));
        b.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 0, 1));
        b.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
        b.addLabel("Yes");
        b.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 0, 2));
        b.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
        return b.getMethodImplementation();
    }

    private static Method method() {
        return (Method) Proxy.newProxyInstance(MultiTemplatePropertyTest.class.getClassLoader(),
                new Class[]{Method.class}, (proxy, called, args) -> {
                    switch (called.getName()) {
                        case "getDefiningClass": return "Lcom/example/Property;";
                        case "getName": return "sample";
                        case "getParameterTypes": return java.util.Collections.emptyList();
                        case "getParameters": return java.util.Collections.emptyList();
                        case "getAccessFlags": return AccessFlags.STATIC.getValue();
                        case "getReturnType": return "V";
                        default: return null;
                    }
                });
    }
}
