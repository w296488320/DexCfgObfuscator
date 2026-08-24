package com.hunter.dexcfgobf.string;

import com.android.build.api.instrumentation.AsmClassVisitorFactory;
import com.android.build.api.instrumentation.ClassContext;
import com.android.build.api.instrumentation.ClassData;
import org.objectweb.asm.ClassVisitor;

/** AGP ASM 入口；application 使用 ALL，library 使用 PROJECT。 */
public abstract class StringEncryptionVisitorFactory
        implements AsmClassVisitorFactory<StringEncryptionParameters> {

    @Override
    public ClassVisitor createClassVisitor(ClassContext classContext, ClassVisitor nextClassVisitor) {
        StringEncryptionContext context = StringEncryptionRegistry.require(
                getParameters().get().getRegistryKey().get());
        return new StringEncryptionClassVisitor(context, nextClassVisitor);
    }

    @Override
    public boolean isInstrumentable(ClassData classData) {
        StringEncryptionContext context = StringEncryptionRegistry.require(
                getParameters().get().getRegistryKey().get());
        return context.shouldVisitClass(classData.getClassName());
    }
}
