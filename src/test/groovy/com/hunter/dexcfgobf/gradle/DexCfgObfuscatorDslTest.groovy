package com.hunter.dexcfgobf.gradle

import com.hunter.dexcfgobf.string.StringEncryptionMode
import org.gradle.api.Action
import org.gradle.api.GradleException
import org.gradle.testfixtures.ProjectBuilder
import org.junit.Test

import static org.junit.Assert.*

class DexCfgObfuscatorDslTest {
    @Test
    void configuresGradleDecoratedExtensionInstance() {
        def project = ProjectBuilder.builder().build()
        DexCfgObfuscatorExtension extension = project.extensions.create(
                'dexControlFlowObfuscator', DexCfgObfuscatorExtension)

        extension.dexObfuscator {
            enabled false
            level ObfuscationLevel.HIGH
            obfClass = ['com.decorated']
        }
        extension.stringEncryption { enabled true }

        assertFalse(extension.dexObfuscator.enabled)
        assertEquals(ObfuscationLevel.HIGH, extension.dexObfuscator.level)
        assertEquals(['com.decorated'], extension.dexObfuscator.obfClass)
        assertTrue(extension.stringEncryption.enabled)
    }

    @Test
    void configuresRealNestedGroovyDsl() {
        DexCfgObfuscatorExtension extension = new DexCfgObfuscatorExtension()

        extension.dexObfuscator {
            enabled true
            level ObfuscationLevel.HIGH
            obfClass = ['com.example', 'example.feature']
            blackClass(['com.example.generated'] as String[])
            minObfuscatedMethods 7
            minFlattenedMethods 3
            minObfuscatedRatio 0.25d
            maxSizeIncreasePercent 45.5d
            adversarialCommands = [['jadx', '{dexDir}']]
            adversarialTimeoutSeconds 15
        }
        extension.stringEncryption {
            enabled true
            mode StringEncryptionMode.BYTES
            packages = ['com.example']
            excludePackages = ['com.example.databinding']
        }

        DexObfuscatorExtension cfg = extension.dexObfuscator
        assertTrue(cfg.enabled)
        assertEquals(ObfuscationLevel.HIGH, cfg.level)
        assertEquals(['com.example', 'example.feature'], cfg.obfClass)
        assertEquals(['com.example.generated'], cfg.blackClass)
        assertEquals(7, cfg.minObfuscatedMethods)
        assertEquals(3, cfg.minFlattenedMethods)
        assertEquals(0.25d, cfg.minObfuscatedRatio, 0.0d)
        assertEquals(45.5d, cfg.maxSizeIncreasePercent, 0.0d)
        assertEquals([['jadx', '{dexDir}']], cfg.adversarialCommands)
        assertEquals(15, cfg.adversarialTimeoutSeconds)
        assertTrue(extension.stringEncryption.enabled)
        assertEquals(StringEncryptionMode.BYTES, extension.stringEncryption.resolvedMode())
    }

    @Test
    void exposesTypedActionOverloadForKotlinStyleConfiguration() {
        DexCfgObfuscatorExtension extension = new DexCfgObfuscatorExtension()
        Action<DexObfuscatorExtension> action = { DexObfuscatorExtension cfg ->
            cfg.enabled = false
            cfg.level = ObfuscationLevel.LOW
            cfg.obfClass = ['com.action']
        } as Action<DexObfuscatorExtension>

        extension.dexObfuscator(action)

        assertFalse(extension.dexObfuscator.enabled)
        assertEquals(ObfuscationLevel.LOW, extension.dexObfuscator.level)
        assertEquals(['com.action'], extension.dexObfuscator.obfClass)
    }

    @Test
    void modulesAndExtensionInstancesKeepIndependentState() {
        DexCfgObfuscatorExtension first = new DexCfgObfuscatorExtension()
        DexCfgObfuscatorExtension second = new DexCfgObfuscatorExtension()

        first.dexObfuscator {
            enabled false
            obfClass = ['com.first']
        }
        first.stringEncryption { enabled true }

        assertNotSame(first.dexObfuscator, second.dexObfuscator)
        assertNotSame(first.stringEncryption, second.stringEncryption)
        assertEquals(['com.first'], first.dexObfuscator.obfClass)
        assertTrue(second.dexObfuscator.obfClass.empty)
        assertTrue(first.stringEncryption.enabled)
        assertFalse(second.stringEncryption.enabled)
    }

    @Test
    void legacyFlatDslDelegatesToSingleCfgObjectAndWarnsOnce() {
        DexCfgObfuscatorExtension extension = new DexCfgObfuscatorExtension()

        extension.enabled false
        extension.level ObfuscationLevel.HIGH
        extension.obfClass(['com.legacy'] as String[])
        extension.blackClass = ['com.legacy.generated']
        extension.minObfuscatedMethods 9
        extension.minFlattenedMethods = 4
        extension.minObfuscatedRatio 0.5d
        extension.maxSizeIncreasePercent = 30.0d
        extension.adversarialCommands([['tool', '{report}']])
        extension.adversarialTimeoutSeconds = 20
        extension.enabledVariants = ['release']

        DexObfuscatorExtension cfg = extension.dexObfuscator
        assertFalse(cfg.enabled)
        assertEquals(ObfuscationLevel.HIGH, cfg.level)
        assertEquals(['com.legacy'], cfg.obfClass)
        assertEquals(['com.legacy.generated'], cfg.blackClass)
        assertEquals(9, cfg.minObfuscatedMethods)
        assertEquals(4, cfg.minFlattenedMethods)
        assertEquals(0.5d, cfg.minObfuscatedRatio, 0.0d)
        assertEquals(30.0d, cfg.maxSizeIncreasePercent, 0.0d)
        assertEquals([['tool', '{report}']], cfg.adversarialCommands)
        assertEquals(20, cfg.adversarialTimeoutSeconds)
        assertEquals(['release'], extension.legacyEnabledVariantsForPlugin())
        assertTrue(extension.consumeLegacyCfgDslWarning())
        assertFalse(extension.consumeLegacyCfgDslWarning())
    }

    @Test
    void preservesLegacyJvmMethodDescriptors() {
        assertNotNull(DexCfgObfuscatorExtension.getDeclaredMethod('isEnabled'))
        assertNotNull(DexCfgObfuscatorExtension.getDeclaredMethod(
                'setEnabledVariants', List))
    }

    @Test
    void refusesMixedLegacyAndNestedCfgDslInBothOrders() {
        DexCfgObfuscatorExtension legacyFirst = new DexCfgObfuscatorExtension()
        legacyFirst.enabled true
        GradleException legacyThenNested = assertThrows(GradleException) {
            legacyFirst.dexObfuscator { level ObfuscationLevel.HIGH }
        }
        assertTrue(legacyThenNested.message.contains('cannot be mixed'))

        DexCfgObfuscatorExtension nestedFirst = new DexCfgObfuscatorExtension()
        nestedFirst.dexObfuscator { enabled true }
        GradleException nestedThenLegacy = assertThrows(GradleException) {
            nestedFirst.enabledVariants = ['release']
        }
        assertTrue(nestedThenLegacy.message.contains('remove the legacy CFG enabledVariants'))
    }

    @Test
    void deprecatedReadsDoNotSelectLegacyDslButDirectChildMutationSelectsNestedDsl() {
        DexCfgObfuscatorExtension readsOnly = new DexCfgObfuscatorExtension()
        assertTrue(readsOnly.enabled)
        assertEquals(ObfuscationLevel.MEDIUM, readsOnly.level)
        assertTrue(readsOnly.obfClass.empty)
        assertTrue(readsOnly.enabledVariants.empty)
        readsOnly.dexObfuscator { enabled false }
        assertFalse(readsOnly.dexObfuscator.enabled)

        DexCfgObfuscatorExtension childFirst = new DexCfgObfuscatorExtension()
        childFirst.dexObfuscator.enabled = false
        assertThrows(GradleException) { childFirst.level = ObfuscationLevel.HIGH }

        DexCfgObfuscatorExtension legacyFirst = new DexCfgObfuscatorExtension()
        legacyFirst.level = ObfuscationLevel.LOW
        assertThrows(GradleException) {
            legacyFirst.dexObfuscator.enabled = false
        }
    }

    @Test
    void newCfgModuleDoesNotExposeVariantSelector() {
        DexObfuscatorExtension cfg = new DexCfgObfuscatorExtension().dexObfuscator
        assertNull(cfg.metaClass.hasProperty(cfg, 'enabledVariants'))
        assertThrows(MissingPropertyException) {
            cfg.enabledVariants = ['release']
        }
    }

    @Test
    void stringFogAliasesOnlyConfigureStringModule() {
        DexCfgObfuscatorExtension upper = new DexCfgObfuscatorExtension()
        DexCfgObfuscatorExtension lower = new DexCfgObfuscatorExtension()

        upper.stringFog { enabled true }
        lower.stringfog { enabled true }

        assertTrue(upper.stringEncryption.enabled)
        assertTrue(lower.stringEncryption.enabled)
        assertTrue(upper.dexObfuscator.enabled)
        assertTrue(lower.dexObfuscator.enabled)
    }
}
