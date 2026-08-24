package com.hunter.dexcfgobf.gradle

import groovy.transform.PackageScope
import org.gradle.api.GradleException

/** Shared origin tracking that remains stable when Gradle decorates the public extension class. */
@PackageScope
class CfgDslUsageState {
    private boolean nestedCfgDslUsed = false
    private boolean legacyCfgDslUsed = false
    private boolean legacyCfgWarningEmitted = false
    private int legacyMutationDepth = 0
    private String firstLegacyCfgProperty

    void markNested() {
        if (legacyMutationDepth > 0) return
        if (legacyCfgDslUsed) throw mixedDslFailure(firstLegacyCfgProperty)
        nestedCfgDslUsed = true
    }

    void mutateLegacy(String propertyName, Closure<?> mutation) {
        markLegacy(propertyName)
        legacyMutationDepth++
        try {
            mutation.call()
        } finally {
            legacyMutationDepth--
        }
    }

    void markLegacy(String propertyName) {
        if (nestedCfgDslUsed) throw mixedDslFailure(propertyName)
        legacyCfgDslUsed = true
        if (firstLegacyCfgProperty == null) firstLegacyCfgProperty = propertyName
    }

    synchronized boolean consumeLegacyWarning() {
        if (!legacyCfgDslUsed || legacyCfgWarningEmitted) return false
        legacyCfgWarningEmitted = true
        return true
    }

    String firstLegacyProperty() { firstLegacyCfgProperty ?: 'CFG property' }

    private static GradleException mixedDslFailure(String legacyProperty) {
        new GradleException("[dex-cfg-obf] legacy top-level CFG property '${legacyProperty}' " +
                'cannot be mixed with dexObfuscator { ... }; move every CFG property into ' +
                'dexObfuscator and remove the legacy CFG enabledVariants selector')
    }
}
