package com.hunter.dexcfgobf.gradle

import groovy.transform.PackageScope

/**
 * dexControlFlowObfuscator.dexObfuscator 的配置。
 *
 * CFG 是 application 最终 DEX 上的独立保护模块。enabled=true 表示对该
 * application 的全部 variant 生效；是否构建某个 variant 由调用方的 Gradle task 决定。
 */
class DexObfuscatorExtension {
    private final CfgDslUsageState usageState
    /** 是否启用 application 后置 DEX CFG 混淆。 */
    private boolean enabledValue = true
    /** 混淆等级，默认在复杂度、体积和 verifier 稳定性之间取平衡。 */
    private ObfuscationLevel levelValue = ObfuscationLevel.MEDIUM
    /** 需要混淆的包/类前缀。点分或斜杠均可。 */
    private List<String> obfClassValue = []
    /** 例外前缀：命中则不混淆。 */
    private List<String> blackClassValue = []
    /** CFG 质量门禁：实际混淆方法数不得低于该值；0 表示不限制。 */
    private int minObfuscatedMethodsValue = 0
    /** CFG 质量门禁：强平坦化方法数下限；reorder 不计入。 */
    private int minFlattenedMethodsValue = 0
    /** CFG 质量门禁：混淆方法数 / 扫描方法数；0 表示不限制。 */
    private double minObfuscatedRatioValue = 0.0d
    /** CFG 体积门禁：DEX 总增幅百分比不得超过该值。 */
    private double maxSizeIncreasePercentValue = 100.0d
    /**
     * 可选对抗命令，每项必须是参数数组而非 shell 字符串。
     * 支持占位符 {dexDir}/{report}/{variant}，非零退出或超时会让构建失败。
     */
    private List<List<String>> adversarialCommandsValue = []
    private int adversarialTimeoutSecondsValue = 300

    DexObfuscatorExtension() {
        this(null)
    }

    @PackageScope DexObfuscatorExtension(CfgDslUsageState usageState) {
        this.usageState = usageState
    }

    boolean getEnabled() { enabledValue }
    boolean isEnabled() { enabledValue }
    void setEnabled(boolean value) { beforeMutation(); enabledValue = value }
    ObfuscationLevel getLevel() { levelValue }
    void setLevel(ObfuscationLevel value) { beforeMutation(); levelValue = value }
    List<String> getObfClass() { obfClassValue }
    void setObfClass(List<String> value) { beforeMutation(); obfClassValue = value }
    List<String> getBlackClass() { blackClassValue }
    void setBlackClass(List<String> value) { beforeMutation(); blackClassValue = value }
    int getMinObfuscatedMethods() { minObfuscatedMethodsValue }
    void setMinObfuscatedMethods(int value) { beforeMutation(); minObfuscatedMethodsValue = value }
    int getMinFlattenedMethods() { minFlattenedMethodsValue }
    void setMinFlattenedMethods(int value) { beforeMutation(); minFlattenedMethodsValue = value }
    double getMinObfuscatedRatio() { minObfuscatedRatioValue }
    void setMinObfuscatedRatio(double value) { beforeMutation(); minObfuscatedRatioValue = value }
    double getMaxSizeIncreasePercent() { maxSizeIncreasePercentValue }
    void setMaxSizeIncreasePercent(double value) {
        beforeMutation(); maxSizeIncreasePercentValue = value
    }
    List<List<String>> getAdversarialCommands() { adversarialCommandsValue }
    void setAdversarialCommands(List<List<String>> value) {
        beforeMutation(); adversarialCommandsValue = value
    }
    int getAdversarialTimeoutSeconds() { adversarialTimeoutSecondsValue }
    void setAdversarialTimeoutSeconds(int value) {
        beforeMutation(); adversarialTimeoutSecondsValue = value
    }

    // 普通嵌套对象没有 Gradle 顶层 Extension 的动态 property-to-method 适配，
    // 显式提供 command-style 方法，确保 Groovy DSL 的 `enabled true` 等写法稳定。
    void enable(boolean value) { setEnabled(value) }
    void enabled(boolean value) { setEnabled(value) }
    void level(ObfuscationLevel value) { setLevel(value) }
    void obfClass(Object value) { setObfClass(strings(value)) }
    void blackClass(Object value) { setBlackClass(strings(value)) }
    void minObfuscatedMethods(int value) { setMinObfuscatedMethods(value) }
    void minFlattenedMethods(int value) { setMinFlattenedMethods(value) }
    void minObfuscatedRatio(double value) { setMinObfuscatedRatio(value) }
    void maxSizeIncreasePercent(double value) { setMaxSizeIncreasePercent(value) }
    void adversarialCommands(Object value) { setAdversarialCommands(commands(value)) }
    void adversarialTimeoutSeconds(int value) { setAdversarialTimeoutSeconds(value) }

    private void beforeMutation() {
        if (usageState != null) usageState.markNested()
    }

    private static List<String> strings(Object value) {
        if (value == null) return []
        if (value instanceof Collection) {
            return value.collect { it == null ? null : it.toString() }.findAll { it != null }
        }
        if (value.getClass().isArray()) {
            return Arrays.asList((Object[]) value)
                    .collect { it == null ? null : it.toString() }.findAll { it != null }
        }
        return [value.toString()]
    }

    private static List<List<String>> commands(Object value) {
        if (value == null) return []
        Collection<?> entries
        if (value instanceof Collection) {
            entries = (Collection<?>) value
        } else if (value.getClass().isArray()) {
            entries = Arrays.asList((Object[]) value)
        } else {
            entries = [value]
        }
        return entries.collect { Object command -> strings(command) }
    }
}
