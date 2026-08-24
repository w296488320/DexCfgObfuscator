package com.hunter.dexcfgobf.gradle

import org.gradle.api.Action

/**
 * DSL 扩展：dexControlFlowObfuscator { ... }
 * 仅公开稳定且确实需要宿主选择的配置，其余安全能力由插件默认开启。
 */
class DexCfgObfuscatorExtension {
    /** 是否启用 application 后置 DEX CFG 混淆；不控制独立的字符串阶段。 */
    boolean enabled = true
    /**
     * CFG 生效的 variantName 或 buildType（大小写不敏感）；空列表表示所有 application variant。
     * 该过滤器不影响始终独立运行的字符串阶段。
     */
    List<String> enabledVariants = []
    /** 混淆等级，默认在复杂度、体积和 verifier 稳定性之间取平衡。 */
    ObfuscationLevel level = ObfuscationLevel.MEDIUM
    /** 需要混淆的包/类前缀（对齐 BlackObfuscator.obfClass）。点分或斜杠均可。 */
    List<String> obfClass = []
    /** 例外前缀：命中则不混淆（对齐 BlackObfuscator.blackClass）。 */
    List<String> blackClass = []
    /** CFG 质量门禁：实际混淆方法数不得低于该值；0 表示不限制。 */
    int minObfuscatedMethods = 0
    /** CFG 质量门禁：强平坦化方法数下限；reorder 不计入。 */
    int minFlattenedMethods = 0
    /** CFG 质量门禁：混淆方法数 / 扫描方法数；0 表示不限制。 */
    double minObfuscatedRatio = 0.0d
    /** CFG 体积门禁：DEX 总增幅百分比不得超过该值。 */
    double maxSizeIncreasePercent = 100.0d
    /**
     * 可选对抗命令，每项必须是参数数组而非 shell 字符串。
     * 支持占位符 {dexDir}/{report}/{variant}，非零退出或超时会让构建失败。
     */
    List<List<String>> adversarialCommands = []
    int adversarialTimeoutSeconds = 300

    /**
     * D8/R8 前执行的字符串保护阶段。默认关闭以保持 0.0.x 老配置的产物行为不变。
     * 未单独配置 packages/excludePackages 时分别继承 obfClass/blackClass；显式 [] 不继承。
     */
    final StringEncryptionExtension stringEncryption = new StringEncryptionExtension()

    void enabledVariants(Object value) {
        enabledVariants = variantStrings(value)
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
    void stringFog(Closure<?> configure) {
        stringEncryption(configure)
    }

    void stringFog(Action<? super StringEncryptionExtension> configure) {
        stringEncryption(configure)
    }

    void stringfog(Closure<?> configure) {
        stringEncryption(configure)
    }

    void stringfog(Action<? super StringEncryptionExtension> configure) {
        stringEncryption(configure)
    }

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
