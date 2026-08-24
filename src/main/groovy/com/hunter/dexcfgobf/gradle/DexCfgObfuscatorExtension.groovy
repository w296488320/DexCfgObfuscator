package com.hunter.dexcfgobf.gradle

import groovy.transform.PackageScope
import org.gradle.api.Action

/**
 * 根 DSL 容器：dexControlFlowObfuscator { dexObfuscator { ... }; stringEncryption { ... } }
 *
 * 每项保护能力拥有独立子扩展。0.0.16 暂时保留旧平铺 CFG 字段作为迁移别名；
 * 新旧 CFG 写法不能混用，避免配置覆盖顺序产生不明确的保护结果。
 */
class DexCfgObfuscatorExtension {
    private final CfgDslUsageState cfgDslUsage = new CfgDslUsageState()
    final DexObfuscatorExtension dexObfuscator = new DexObfuscatorExtension(cfgDslUsage)
    final StringEncryptionExtension stringEncryption = new StringEncryptionExtension()

    private List<String> legacyEnabledVariants = []

    void dexObfuscator(Closure<?> configure) {
        markNestedCfgDsl()
        Closure<?> nested = (Closure<?>) configure.rehydrate(
                dexObfuscator, configure.owner, configure.thisObject)
        nested.resolveStrategy = Closure.DELEGATE_FIRST
        nested.call()
    }

    void dexObfuscator(Action<? super DexObfuscatorExtension> configure) {
        markNestedCfgDsl()
        configure.execute(dexObfuscator)
    }

    void stringEncryption(Closure<?> configure) {
        Closure<?> nested = (Closure<?>) configure.rehydrate(
                stringEncryption, configure.owner, configure.thisObject)
        nested.resolveStrategy = Closure.DELEGATE_FIRST
        nested.call()
    }

    void stringEncryption(Action<? super StringEncryptionExtension> configure) {
        configure.execute(stringEncryption)
    }

    /** 便于从旧 StringFog 配置迁移的 DSL 别名。 */
    void stringFog(Closure<?> configure) { stringEncryption(configure) }
    void stringFog(Action<? super StringEncryptionExtension> configure) {
        stringEncryption(configure)
    }
    void stringfog(Closure<?> configure) { stringEncryption(configure) }
    void stringfog(Action<? super StringEncryptionExtension> configure) {
        stringEncryption(configure)
    }

    /*
     * 0.0.15 及更早版本的平铺 CFG DSL 兼容层。所有字段直接委托给唯一的
     * dexObfuscator 对象；enabledVariants 只保留旧脚本的 release-only 语义，
     * 新 dexObfuscator 模块不再公开 variant selector。
     */
    @Deprecated boolean getEnabled() { dexObfuscator.enabled }
    /** Retains the exact accessor emitted by the 0.0.15 Groovy boolean property. */
    @Deprecated boolean isEnabled() { dexObfuscator.enabled }
    @Deprecated void setEnabled(boolean value) {
        mutateLegacyCfg('enabled') { dexObfuscator.enabled = value }
    }
    @Deprecated void enable(boolean value) { setEnabled(value) }
    @Deprecated void enabled(boolean value) { setEnabled(value) }

    @Deprecated ObfuscationLevel getLevel() { dexObfuscator.level }
    @Deprecated void setLevel(ObfuscationLevel value) {
        mutateLegacyCfg('level') { dexObfuscator.level = value }
    }
    @Deprecated void level(ObfuscationLevel value) { setLevel(value) }

    @Deprecated List<String> getObfClass() { dexObfuscator.obfClass }
    @Deprecated void setObfClass(List<String> value) {
        mutateLegacyCfg('obfClass') { dexObfuscator.obfClass = value }
    }
    @Deprecated void obfClass(Object value) {
        mutateLegacyCfg('obfClass') { dexObfuscator.obfClass(value) }
    }

    @Deprecated List<String> getBlackClass() {
        dexObfuscator.blackClass
    }
    @Deprecated void setBlackClass(List<String> value) {
        mutateLegacyCfg('blackClass') { dexObfuscator.blackClass = value }
    }
    @Deprecated void blackClass(Object value) {
        mutateLegacyCfg('blackClass') { dexObfuscator.blackClass(value) }
    }

    @Deprecated int getMinObfuscatedMethods() {
        dexObfuscator.minObfuscatedMethods
    }
    @Deprecated void setMinObfuscatedMethods(int value) {
        mutateLegacyCfg('minObfuscatedMethods') { dexObfuscator.minObfuscatedMethods = value }
    }
    @Deprecated void minObfuscatedMethods(int value) { setMinObfuscatedMethods(value) }

    @Deprecated int getMinFlattenedMethods() {
        dexObfuscator.minFlattenedMethods
    }
    @Deprecated void setMinFlattenedMethods(int value) {
        mutateLegacyCfg('minFlattenedMethods') { dexObfuscator.minFlattenedMethods = value }
    }
    @Deprecated void minFlattenedMethods(int value) { setMinFlattenedMethods(value) }

    @Deprecated double getMinObfuscatedRatio() {
        dexObfuscator.minObfuscatedRatio
    }
    @Deprecated void setMinObfuscatedRatio(double value) {
        mutateLegacyCfg('minObfuscatedRatio') { dexObfuscator.minObfuscatedRatio = value }
    }
    @Deprecated void minObfuscatedRatio(double value) { setMinObfuscatedRatio(value) }

    @Deprecated double getMaxSizeIncreasePercent() {
        dexObfuscator.maxSizeIncreasePercent
    }
    @Deprecated void setMaxSizeIncreasePercent(double value) {
        mutateLegacyCfg('maxSizeIncreasePercent') {
            dexObfuscator.maxSizeIncreasePercent = value
        }
    }
    @Deprecated void maxSizeIncreasePercent(double value) { setMaxSizeIncreasePercent(value) }

    @Deprecated List<List<String>> getAdversarialCommands() {
        dexObfuscator.adversarialCommands
    }
    @Deprecated void setAdversarialCommands(List<List<String>> value) {
        mutateLegacyCfg('adversarialCommands') { dexObfuscator.adversarialCommands = value }
    }
    @Deprecated void adversarialCommands(Object value) {
        mutateLegacyCfg('adversarialCommands') { dexObfuscator.adversarialCommands(value) }
    }

    @Deprecated int getAdversarialTimeoutSeconds() {
        dexObfuscator.adversarialTimeoutSeconds
    }
    @Deprecated void setAdversarialTimeoutSeconds(int value) {
        mutateLegacyCfg('adversarialTimeoutSeconds') {
            dexObfuscator.adversarialTimeoutSeconds = value
        }
    }
    @Deprecated void adversarialTimeoutSeconds(int value) {
        setAdversarialTimeoutSeconds(value)
    }

    @Deprecated List<String> getEnabledVariants() {
        legacyEnabledVariants
    }
    /** Retains the exact setter descriptor emitted by the 0.0.15 Groovy List property. */
    @Deprecated void setEnabledVariants(List<String> value) {
        markLegacyCfgDsl('enabledVariants')
        legacyEnabledVariants = value == null ? null : new ArrayList<>(value)
    }
    @Deprecated void enabledVariants(Object value) {
        setEnabledVariants(variantStrings(value))
    }

    /** Plugin-only compatibility view; unlike deprecated getters this never marks DSL usage. */
    @PackageScope List<String> legacyEnabledVariantsForPlugin() {
        legacyEnabledVariants == null
                ? null : Collections.unmodifiableList(legacyEnabledVariants)
    }

    /** Returns true once so a multi-variant build emits one migration warning. */
    @PackageScope synchronized boolean consumeLegacyCfgDslWarning() {
        cfgDslUsage.consumeLegacyWarning()
    }

    @PackageScope String firstLegacyCfgPropertyForPlugin() {
        cfgDslUsage.firstLegacyProperty()
    }

    private void markNestedCfgDsl() {
        cfgDslUsage.markNested()
    }

    private void mutateLegacyCfg(String propertyName, Closure<?> mutation) {
        cfgDslUsage.mutateLegacy(propertyName, mutation)
    }

    private void markLegacyCfgDsl(String propertyName) {
        cfgDslUsage.markLegacy(propertyName)
    }

    /** Preserve null entries so the selector validator fails instead of enabling all variants. */
    private static List<String> variantStrings(Object value) {
        if (value == null) return [null]
        if (value instanceof Collection) {
            return value.collect { it == null ? null : it.toString() }
        }
        if (value.getClass().isArray()) {
            return Arrays.asList((Object[]) value)
                    .collect { it == null ? null : it.toString() }
        }
        return [value.toString()]
    }
}
