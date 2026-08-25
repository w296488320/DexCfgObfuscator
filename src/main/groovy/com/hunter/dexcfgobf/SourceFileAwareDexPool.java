package com.hunter.dexcfgobf;

import com.android.tools.smali.dexlib2.DebugItemType;
import com.android.tools.smali.dexlib2.Opcodes;
import com.android.tools.smali.dexlib2.iface.debug.DebugItem;
import com.android.tools.smali.dexlib2.iface.debug.SetSourceFile;
import com.android.tools.smali.dexlib2.writer.DebugWriter;
import com.android.tools.smali.dexlib2.writer.pool.ClassPool;
import com.android.tools.smali.dexlib2.writer.pool.DexPool;

import java.io.IOException;

/**
 * DexPool with a narrow workaround for smali-dexlib2 3.0.9 SET_SOURCE_FILE serialization.
 *
 * <p>That version's {@code ClassPool.writeDebugItem} writes SET_SOURCE_FILE and then falls through
 * to its default branch because the switch case is missing a break. Any otherwise valid method
 * containing DBG_SET_FILE consequently fails with "Unexpected debug item type: 9". Keep all pool
 * behavior unchanged and intercept only that item until the upstream dependency contains the
 * missing break.</p>
 */
final class SourceFileAwareDexPool extends DexPool {

    SourceFileAwareDexPool(Opcodes opcodes) {
        super(opcodes);
    }

    @Override
    protected SectionProvider getSectionProvider() {
        return new SourceFileAwareSectionProvider();
    }

    private final class SourceFileAwareSectionProvider extends DexPoolSectionProvider {
        @Override
        public ClassPool getClassSection() {
            return new SourceFileAwareClassPool(SourceFileAwareDexPool.this);
        }
    }

    private static final class SourceFileAwareClassPool extends ClassPool {
        SourceFileAwareClassPool(DexPool dexPool) {
            super(dexPool);
        }

        @Override
        public void writeDebugItem(DebugWriter<CharSequence, CharSequence> writer,
                                   DebugItem debugItem) throws IOException {
            if (debugItem.getDebugItemType() == DebugItemType.SET_SOURCE_FILE) {
                SetSourceFile sourceFile = (SetSourceFile) debugItem;
                writer.writeSetSourceFile(sourceFile.getCodeAddress(), sourceFile.getSourceFile());
                return;
            }
            super.writeDebugItem(writer, debugItem);
        }
    }
}
