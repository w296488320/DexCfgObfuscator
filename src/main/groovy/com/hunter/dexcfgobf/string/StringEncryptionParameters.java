package com.hunter.dexcfgobf.string;

import com.android.build.api.instrumentation.InstrumentationParameters;
import org.gradle.api.provider.Property;
import org.gradle.api.tasks.Input;

public interface StringEncryptionParameters extends InstrumentationParameters {
    @Input
    Property<String> getRegistryKey();

    /** Force AGP artifact transforms to execute for a strict or explicitly requested full run. */
    @Input
    Property<String> getFullCoverageInvocationNonce();
}
