package com.hunter.dexcfgobf;

import com.android.tools.smali.dexlib2.AccessFlags;
import com.android.tools.smali.dexlib2.DexFileFactory;
import com.android.tools.smali.dexlib2.Opcode;
import com.android.tools.smali.dexlib2.Opcodes;
import com.android.tools.smali.dexlib2.builder.Label;
import com.android.tools.smali.dexlib2.builder.MethodImplementationBuilder;
import com.android.tools.smali.dexlib2.iface.Method;
import com.android.tools.smali.dexlib2.iface.MethodImplementation;
import com.android.tools.smali.dexlib2.iface.ClassDef;
import com.android.tools.smali.dexlib2.iface.debug.DebugItem;
import com.android.tools.smali.dexlib2.iface.debug.LineNumber;
import com.android.tools.smali.dexlib2.iface.debug.SetSourceFile;
import com.android.tools.smali.dexlib2.iface.instruction.Instruction;
import com.android.tools.smali.dexlib2.iface.instruction.NarrowLiteralInstruction;
import com.android.tools.smali.dexlib2.iface.instruction.OneRegisterInstruction;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction10x;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction11n;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction21t;
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableStringReference;
import com.android.tools.smali.dexlib2.immutable.ImmutableClassDef;
import com.android.tools.smali.dexlib2.immutable.ImmutableMethod;
import com.android.tools.smali.dexlib2.writer.io.FileDataStore;
import com.android.tools.smali.dexlib2.writer.pool.DexPool;

import org.junit.Test;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/** Stack-trace position preservation across strong flattening and safe block reordering. */
public class CfgDebugPositionTest {

    @Test
    public void stackTracePositionsArePreservedByDefault() {
        assertFalse(new ObfuscatorConfig().stripDebugInfo);
    }

    @Test
    public void strongFlatteningReplaysOriginalLineAndSourceAtShiftedBusinessInstructions() {
        MethodImplementation source = positionedBranchMethod();
        ObfuscatorConfig config = config(false);
        ObfuscatorStats stats = new ObfuscatorStats();

        MethodImplementation output = new CfgFlattener(
                config, ObfuscatorLogger.STDOUT, stats).flatten(method("run", true), source);

        assertNotNull(output);
        assertEquals(1, stats.methodsFlattened);
        List<ObservedInstruction> observed = observe(output);
        // Strong flattening shifts the original v0 to v4. Glue uses the reserved v0..v3 range.
        assertHasLiteral(observed, 4, 0, 500, "First.java");
        assertHasOpcodeOnRegister(observed, Opcode.IF_EQZ, 4, 100, "First.java");
        assertHasLiteral(observed, 4, 1, 300, "First.java");
        assertHasLiteral(observed, 4, 2, 20, "Second.kt");
        assertHasOpcode(observed, Opcode.RETURN_VOID, 301, "First.java");
        assertHasOpcode(observed, Opcode.RETURN_VOID, 21, "Second.kt");
        assertAllLinesPositive(output);
    }

    @Test
    public void reorderedBlocksPreserveDecreasingLinesAndPerBlockSourceFiles() {
        MethodImplementation source = positionedBranchMethod();
        ObfuscatorConfig config = config(false);
        ObfuscatorStats stats = new ObfuscatorStats();

        // A non-static constructor is outside the strong-flatten whitelist and exercises reorder.
        MethodImplementation output = new CfgFlattener(
                config, ObfuscatorLogger.STDOUT, stats).flatten(method("<init>", false), source);

        assertNotNull(output);
        assertEquals(1, stats.methodsReordered);
        List<ObservedInstruction> observed = observe(output);
        assertHasLiteral(observed, 0, 0, 500, "First.java");
        assertHasOpcodeOnRegister(observed, Opcode.IF_EQZ, 0, 100, "First.java");
        assertHasLiteral(observed, 0, 1, 300, "First.java");
        assertHasLiteral(observed, 0, 2, 20, "Second.kt");

        // 500 -> 100 occurs inside the original entry block. The encoder must retain the negative
        // line delta even though complete blocks are emitted in a shuffled physical order.
        Integer previous = null;
        boolean sawDecrease = false;
        for (DebugItem item : debugItems(output)) {
            if (item instanceof LineNumber) {
                int line = ((LineNumber) item).getLineNumber();
                if (previous != null && line < previous) sawDecrease = true;
                previous = line;
            }
        }
        assertTrue("reordered debug program should support decreasing line deltas", sawDecrease);
        assertAllLinesPositive(output);
    }

    @Test
    public void methodWithoutLineOrSourceItemsStaysWithoutDebugPositions() {
        MethodImplementationBuilder builder = plainBranchMethod();
        MethodImplementation output = new CfgFlattener(
                config(false), ObfuscatorLogger.STDOUT, new ObfuscatorStats())
                .flatten(method("run", true), builder.getMethodImplementation());

        assertNotNull(output);
        for (DebugItem item : output.getDebugItems()) {
            assertFalse(item instanceof LineNumber);
            assertFalse(item instanceof SetSourceFile);
        }
    }

    @Test
    public void explicitStripDebugInfoKeepsLegacyUnknownSourceBehavior() {
        MethodImplementation output = new CfgFlattener(
                config(true), ObfuscatorLogger.STDOUT, new ObfuscatorStats())
                .flatten(method("run", true), positionedBranchMethod());

        assertNotNull(output);
        for (DebugItem item : output.getDebugItems()) {
            assertFalse(item instanceof LineNumber);
            assertFalse(item instanceof SetSourceFile);
        }
    }

    @Test
    public void firstPositiveLineBackfillsInstructionsBeforeTheFirstLineEvent() {
        MethodImplementationBuilder builder = new MethodImplementationBuilder(1);
        Label alternate = builder.getLabel("alternate");
        // No line at address 0. The first valid DEX line starts at the conditional.
        builder.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 0, 0));
        builder.addLineNumber(42);
        builder.addInstruction(new BuilderInstruction21t(Opcode.IF_EQZ, 0, alternate));
        builder.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 0, 1));
        builder.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
        builder.addLabel("alternate");
        builder.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 0, 2));
        builder.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));

        MethodImplementation output = new CfgFlattener(
                config(false), ObfuscatorLogger.STDOUT, new ObfuscatorStats())
                .flatten(method("run", true), builder.getMethodImplementation());

        assertNotNull(output);
        assertHasLiteral(observe(output), 4, 0, 42, null);
        assertAllLinesPositive(output);
    }

    @Test
    public void dexPoolRoundTripRetainsTransformedLineAndSourceItems() throws Exception {
        MethodImplementation output = new CfgFlattener(
                config(false), ObfuscatorLogger.STDOUT, new ObfuscatorStats())
                .flatten(method("run", true), positionedBranchMethod());
        assertNotNull(output);

        String owner = "Lcom/example/Positioned;";
        ImmutableMethod transformed = new ImmutableMethod(owner, "run",
                Collections.emptyList(), "V",
                AccessFlags.PUBLIC.getValue() | AccessFlags.STATIC.getValue(),
                Collections.emptySet(), Collections.emptySet(), output);
        ImmutableClassDef classDef = new ImmutableClassDef(owner,
                AccessFlags.PUBLIC.getValue(), "Ljava/lang/Object;", Collections.emptyList(),
                "Positioned.java", Collections.emptySet(), Collections.emptyList(),
                Collections.emptyList(), new LinkedHashSet<>(Collections.singleton(transformed)),
                Collections.emptySet());
        DexPool pool = new SourceFileAwareDexPool(Opcodes.getDefault());
        pool.internClass(classDef);

        Path dex = Files.createTempFile("dex-cfg-debug-position-", ".dex");
        try {
            pool.writeTo(new FileDataStore(dex.toFile()));
            com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile readBack =
                    DexFileFactory.loadDexFile(dex.toFile(), Opcodes.getDefault());
            MethodImplementation implementation = null;
            for (ClassDef readClass : readBack.getClasses()) {
                if (!owner.equals(readClass.getType())) continue;
                for (Method readMethod : readClass.getMethods()) {
                    if ("run".equals(readMethod.getName())) {
                        implementation = readMethod.getImplementation();
                    }
                }
            }
            assertNotNull("round-tripped transformed method not found", implementation);
            boolean sawLine = false;
            boolean sawSourceFile = false;
            for (DebugItem item : implementation.getDebugItems()) {
                if (item instanceof LineNumber) {
                    sawLine = true;
                    assertTrue(((LineNumber) item).getLineNumber() >= 1);
                } else if (item instanceof SetSourceFile) {
                    String sourceFile = ((SetSourceFile) item).getSourceFile();
                    sawSourceFile |= "First.java".equals(sourceFile)
                            || "Second.kt".equals(sourceFile);
                }
            }
            assertTrue("LineNumber items must survive ImmutableMethod/DexPool", sawLine);
            assertTrue("SetSourceFile items must survive ImmutableMethod/DexPool", sawSourceFile);
        } finally {
            Files.deleteIfExists(dex);
        }
    }

    private static MethodImplementation positionedBranchMethod() {
        // Rebuild with deliberate line regressions and two source-file states. Debug events are
        // attached before their corresponding instruction, as required by dexlib2's builder.
        MethodImplementationBuilder positioned = new MethodImplementationBuilder(1);
        Label alternate = positioned.getLabel("alternate");
        positioned.addSetSourceFile(new ImmutableStringReference("First.java"));
        positioned.addLineNumber(500);
        positioned.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 0, 0));
        positioned.addLineNumber(100);
        positioned.addInstruction(new BuilderInstruction21t(Opcode.IF_EQZ, 0, alternate));
        positioned.addLineNumber(300);
        positioned.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 0, 1));
        positioned.addLineNumber(301);
        positioned.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
        positioned.addLabel("alternate");
        positioned.addSetSourceFile(new ImmutableStringReference("Second.kt"));
        positioned.addLineNumber(20);
        positioned.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 0, 2));
        positioned.addLineNumber(21);
        positioned.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
        return positioned.getMethodImplementation();
    }

    private static MethodImplementationBuilder plainBranchMethod() {
        MethodImplementationBuilder builder = new MethodImplementationBuilder(1);
        Label alternate = builder.getLabel("alternate");
        builder.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 0, 0));
        builder.addInstruction(new BuilderInstruction21t(Opcode.IF_EQZ, 0, alternate));
        builder.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 0, 1));
        builder.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
        builder.addLabel("alternate");
        builder.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 0, 2));
        builder.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
        return builder;
    }

    private static ObfuscatorConfig config(boolean stripDebugInfo) {
        ObfuscatorConfig config = new ObfuscatorConfig();
        config.depth = 2;
        config.stripDebugInfo = stripDebugInfo;
        return config;
    }

    private static List<DebugItem> debugItems(MethodImplementation implementation) {
        List<DebugItem> items = new ArrayList<>();
        for (DebugItem item : implementation.getDebugItems()) items.add(item);
        items.sort(Comparator.comparingInt(DebugItem::getCodeAddress));
        return items;
    }

    private static void assertAllLinesPositive(MethodImplementation implementation) {
        for (DebugItem item : implementation.getDebugItems()) {
            if (item instanceof LineNumber) {
                assertTrue("DEX line numbers must be positive",
                        ((LineNumber) item).getLineNumber() >= 1);
            }
        }
    }

    private static List<ObservedInstruction> observe(MethodImplementation implementation) {
        List<DebugItem> items = debugItems(implementation);
        List<ObservedInstruction> observed = new ArrayList<>();
        int itemIndex = 0;
        int address = 0;
        Integer line = null;
        String source = null;
        for (Instruction instruction : implementation.getInstructions()) {
            while (itemIndex < items.size() && items.get(itemIndex).getCodeAddress() <= address) {
                DebugItem item = items.get(itemIndex++);
                if (item instanceof LineNumber) line = ((LineNumber) item).getLineNumber();
                else if (item instanceof SetSourceFile) source = ((SetSourceFile) item).getSourceFile();
            }
            observed.add(new ObservedInstruction(instruction, line, source));
            address += instruction.getCodeUnits();
        }
        return observed;
    }

    private static void assertHasLiteral(List<ObservedInstruction> instructions,
                                         int register, int literal, int line, String source) {
        for (ObservedInstruction observed : instructions) {
            if (observed.instruction instanceof OneRegisterInstruction
                    && observed.instruction instanceof NarrowLiteralInstruction
                    && ((OneRegisterInstruction) observed.instruction).getRegisterA() == register
                    && ((NarrowLiteralInstruction) observed.instruction).getNarrowLiteral() == literal
                    && equalsPosition(observed, line, source)) {
                return;
            }
        }
        throw new AssertionError("missing literal v" + register + "=" + literal
                + " at " + source + ":" + line);
    }

    private static void assertHasOpcodeOnRegister(List<ObservedInstruction> instructions,
                                                   Opcode opcode, int register,
                                                   int line, String source) {
        for (ObservedInstruction observed : instructions) {
            if (observed.instruction.getOpcode() == opcode
                    && observed.instruction instanceof OneRegisterInstruction
                    && ((OneRegisterInstruction) observed.instruction).getRegisterA() == register
                    && equalsPosition(observed, line, source)) {
                return;
            }
        }
        throw new AssertionError("missing " + opcode + " v" + register
                + " at " + source + ":" + line);
    }

    private static void assertHasOpcode(List<ObservedInstruction> instructions,
                                        Opcode opcode, int line, String source) {
        for (ObservedInstruction observed : instructions) {
            if (observed.instruction.getOpcode() == opcode
                    && equalsPosition(observed, line, source)) {
                return;
            }
        }
        throw new AssertionError("missing " + opcode + " at " + source + ":" + line);
    }

    private static boolean equalsPosition(ObservedInstruction observed, int line, String source) {
        return observed.line != null && observed.line == line
                && java.util.Objects.equals(source, observed.source);
    }

    private static Method method(String name, boolean isStatic) {
        int access = isStatic ? AccessFlags.STATIC.getValue() : 0;
        return (Method) java.lang.reflect.Proxy.newProxyInstance(
                CfgDebugPositionTest.class.getClassLoader(), new Class[]{Method.class},
                (proxy, called, args) -> {
                    switch (called.getName()) {
                        case "getDefiningClass": return "Lcom/example/Positioned;";
                        case "getName": return name;
                        case "getParameterTypes": return java.util.Collections.emptyList();
                        case "getParameters": return java.util.Collections.emptyList();
                        case "getAccessFlags": return access;
                        case "getReturnType": return "V";
                        case "toString": return "Lcom/example/Positioned;->" + name;
                        default: return null;
                    }
                });
    }

    private static final class ObservedInstruction {
        final Instruction instruction;
        final Integer line;
        final String source;

        ObservedInstruction(Instruction instruction, Integer line, String source) {
            this.instruction = instruction;
            this.line = line;
            this.source = source;
        }
    }
}
