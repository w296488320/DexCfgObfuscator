package com.zhenxi.hunter.obfuscator.gradle

/**
 * DSL 扩展：dexControlFlowObfuscator { ... }
 * 语义对齐旧 BlackObfuscator 配置块（enabled/depth/obfClass/blackClass）。
 */
class DexCfgObfuscatorExtension {
    /** 是否启用混淆。默认 true，但仅在 release 变体生效（见 onlyReleaseByDefault）。 */
    boolean enabled = true
    /** 仅在 release 构建启用。 */
    boolean onlyReleaseByDefault = true
    /** 混淆强度（对齐 BlackObfuscator.depth，预留）。 */
    int depth = 2
    /** 需要混淆的包/类前缀（对齐 BlackObfuscator.obfClass）。点分或斜杠均可。 */
    List<String> obfClass = []
    /** 例外前缀：命中则不混淆（对齐 BlackObfuscator.blackClass）。 */
    List<String> blackClass = []
    /** 含 try/catch 的方法是否跳过（稳定优先，默认跳过）。 */
    boolean skipMethodsWithTryCatch = true
    /** 方法指令数上限，超过则跳过（避免逼近 16 位上限）。 */
    int maxInstructions = 1500
}
