package com.hunter.dexcfgobf;

import com.android.tools.smali.dexlib2.builder.MethodImplementationBuilder;
import com.android.tools.smali.dexlib2.iface.MethodImplementation;
import com.android.tools.smali.dexlib2.iface.debug.DebugItem;
import com.android.tools.smali.dexlib2.iface.debug.LineNumber;
import com.android.tools.smali.dexlib2.iface.debug.SetSourceFile;
import com.android.tools.smali.dexlib2.iface.instruction.Instruction;
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableStringReference;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Minimal, register-independent debug provenance for a method transformation.
 *
 * <p>CFG transforms rebuild and physically reorder instructions, so copying the original debug
 * stream by code address would attach source lines to the wrong blocks. This class resolves the
 * effective {@link LineNumber} and {@link SetSourceFile} state at every original instruction and
 * lets an emitter replay that state immediately before the corresponding business instruction in
 * its new location.</p>
 *
 * <p>Local-variable debug items are deliberately not retained here. Register shifting and verifier
 * type separation can move or split their registers, so copying StartLocal/EndLocal/RestartLocal
 * without a full register/scope mapping would publish incorrect debugger state.</p>
 */
final class DebugPositionMap {

    private static final class Position {
        final Integer lineNumber;
        final String sourceFile;

        Position(Integer lineNumber, String sourceFile) {
            this.lineNumber = lineNumber;
            this.sourceFile = sourceFile;
        }
    }

    private final List<Position> positions;
    private final boolean hasLineNumbers;
    private final boolean hasSourceFiles;
    private final Map<MethodImplementationBuilder, EmittedState> emittedStates =
            new IdentityHashMap<>();

    private static final class EmittedState {
        Integer lineNumber;
        String sourceFile;
    }

    private DebugPositionMap(List<Position> positions,
                             boolean hasLineNumbers,
                             boolean hasSourceFiles) {
        this.positions = positions;
        this.hasLineNumbers = hasLineNumbers;
        this.hasSourceFiles = hasSourceFiles;
    }

    /** Capture debug state against the original instruction order before any register rewrite. */
    static DebugPositionMap capture(MethodImplementation implementation) {
        List<Instruction> instructions = new ArrayList<>();
        int lastInstructionAddress = -1;
        int instructionAddress = 0;
        for (Instruction instruction : implementation.getInstructions()) {
            instructions.add(instruction);
            lastInstructionAddress = instructionAddress;
            instructionAddress += instruction.getCodeUnits();
        }

        List<DebugItem> debugItems = new ArrayList<>();
        for (DebugItem item : implementation.getDebugItems()) {
            debugItems.add(item);
        }
        // MethodImplementation promises this order, but sorting keeps programmatic callers safe.
        // List.sort is stable, so multiple events at one address retain their encoded order.
        debugItems.sort(Comparator.comparingInt(DebugItem::getCodeAddress));

        // DEX does not have an "unknown line" state that can safely be replayed as line 0. When
        // the first line event starts after address 0, backfill that first valid source line to the
        // preceding instructions. This mirrors the debug_info line_start state and guarantees that
        // every emitted LineNumber remains a valid positive stack-trace line.
        Integer firstLine = null;
        boolean sawSource = false;
        for (DebugItem item : debugItems) {
            if (item.getCodeAddress() > lastInstructionAddress) continue;
            if (firstLine == null && item instanceof LineNumber
                    && ((LineNumber) item).getLineNumber() > 0) {
                firstLine = ((LineNumber) item).getLineNumber();
            }
            sawSource |= item instanceof SetSourceFile;
        }

        List<Position> positions = new ArrayList<>(instructions.size());
        int debugIndex = 0;
        int codeAddress = 0;
        Integer currentLine = firstLine;
        String currentSource = null;
        for (Instruction instruction : instructions) {
            while (debugIndex < debugItems.size()
                    && debugItems.get(debugIndex).getCodeAddress() <= codeAddress) {
                DebugItem item = debugItems.get(debugIndex++);
                if (item instanceof LineNumber && ((LineNumber) item).getLineNumber() > 0) {
                    currentLine = ((LineNumber) item).getLineNumber();
                } else if (item instanceof SetSourceFile) {
                    currentSource = ((SetSourceFile) item).getSourceFile();
                }
            }
            positions.add(new Position(currentLine, currentSource));
            codeAddress += instruction.getCodeUnits();
        }
        return new DebugPositionMap(positions, firstLine != null, sawSource);
    }

    /** Same instruction cardinality, but intentionally emits no debug positions. */
    DebugPositionMap stripped() {
        return new DebugPositionMap(positions, false, false);
    }

    /**
     * Verify the one-to-one index contract used by register separation and register shifting.
     * A mismatch must skip the transformation rather than attach a valid line to the wrong opcode.
     */
    void requireCompatible(MethodImplementation implementation) {
        int count = 0;
        for (Instruction ignored : implementation.getInstructions()) count++;
        if (count != positions.size()) {
            throw new IllegalStateException("debug/instruction size mismatch: "
                    + positions.size() + " != " + count);
        }
    }

    /** Replay only the minimal position state immediately before an original business instruction. */
    void emit(MethodImplementationBuilder out, int originalInstructionIndex) {
        if (originalInstructionIndex < 0 || originalInstructionIndex >= positions.size()) {
            throw new IllegalArgumentException("bad original instruction index: "
                    + originalInstructionIndex + "/" + positions.size());
        }
        Position position = positions.get(originalInstructionIndex);
        EmittedState emitted = emittedStates.computeIfAbsent(out, ignored -> new EmittedState());

        // If a method ever changes source file, explicitly replay null before instructions that
        // precede its first SetSourceFile event. This prevents a shuffled block from inheriting the
        // source file of the physically preceding block. ClassDef.sourceFile remains the fallback.
        if (hasSourceFiles && !Objects.equals(emitted.sourceFile, position.sourceFile)) {
            out.addSetSourceFile(position.sourceFile == null
                    ? null : new ImmutableStringReference(position.sourceFile));
            emitted.sourceFile = position.sourceFile;
        }
        if (hasLineNumbers && !Objects.equals(emitted.lineNumber, position.lineNumber)) {
            if (position.lineNumber == null || position.lineNumber <= 0) {
                throw new IllegalStateException("invalid captured source line: "
                        + position.lineNumber);
            }
            out.addLineNumber(position.lineNumber);
            emitted.lineNumber = position.lineNumber;
        }
    }
}
