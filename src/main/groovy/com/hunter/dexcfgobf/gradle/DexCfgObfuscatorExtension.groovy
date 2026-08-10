package com.hunter.dexcfgobf.gradle

/**
 * DSL 扩展：dexControlFlowObfuscator { ... }
 * 仅公开稳定且确实需要宿主选择的配置，其余安全能力由插件默认开启。
 */
class DexCfgObfuscatorExtension {
    /** 是否启用混淆。默认对所有 Android application 变体生效。 */
    boolean enabled = true
    /** 混淆等级，默认在复杂度、体积和 verifier 稳定性之间取平衡。 */
    ObfuscationLevel level = ObfuscationLevel.MEDIUM
    /** 需要混淆的包/类前缀（对齐 BlackObfuscator.obfClass）。点分或斜杠均可。 */
    List<String> obfClass = []
    /** 例外前缀：命中则不混淆（对齐 BlackObfuscator.blackClass）。 */
    List<String> blackClass = []
    /**
     * 可选对抗命令，每项必须是参数数组而非 shell 字符串。
     * 支持占位符 {dexDir}/{report}/{variant}，非零退出或超时会让构建失败。
     */
    List<List<String>> adversarialCommands = []
    int adversarialTimeoutSeconds = 300
}
