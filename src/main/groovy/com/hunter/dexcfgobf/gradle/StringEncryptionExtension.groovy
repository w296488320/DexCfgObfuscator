package com.hunter.dexcfgobf.gradle

import com.hunter.dexcfgobf.string.StringEncryptionMode

/**
 * dexControlFlowObfuscator.stringEncryption 的配置。
 *
 * implementation 指向宿主同时放在构建 classpath（常见为 buildSrc）和 Android 源集中的类。
 * 构建期需要 encrypt(String, byte[])，运行期需要 decrypt(byte[], byte[])；可选
 * shouldEncrypt(String) 或兼容 StringFog 的 shouldFog(String)。这些方法按约定反射调用，
 * 因而宿主无需再依赖 StringFog interface artifact。
 */
class StringEncryptionExtension {
    boolean enabled = false
    /** 空表示所有 variant；通常仅独立发布的 library 才需要限制字符串阶段。 */
    List<String> enabledVariants = []
    boolean debug = false
    String implementation
    Object algorithm
    Object keyGenerator
    Object mode = StringEncryptionMode.BYTES
    /** null 表示继承 dexObfuscator.obfClass；显式空列表表示不处理任何包并在配置校验时失败。 */
    List<String> packages
    /** null 表示继承 dexObfuscator.blackClass；显式空列表表示不继承任何 CFG 排除项。 */
    List<String> excludePackages
    long seed = 0x6D0F27BD4A91C35EL
    int maxStringBytes = 4096
    boolean decryptorStatic = false
    boolean verifyRoundTrip = true
    boolean allowIdentityCiphertext = false
    /** 无法安全动态改写的 executable bootstrap String 默认让构建失败，避免静默明文。 */
    boolean failOnUnsupportedStringConstants = true
    /** 最终 application DEX string pool 中不得再出现本轮已加密原文。 */
    boolean verifyFinalDex = true
    /** verifyFinalDex 发现泄漏时是否直接让构建失败。 */
    boolean failOnPlaintextLeak = true
    /**
     * 默认对 exact final method 执行点做硬门禁；静态字段的真实执行点按 <clinit> 处理。
     * R8 后仍无法安全解析的少量 hash 会退化为全 DEX runtime-payload 硬门禁，
     * 其余 annotation/call-site 同值仍扫描并报告为碰撞诊断。
     * true 恢复保守的整个 DEX string pool 同值即失败；class/member/debug 等名称也会命中。
     */
    boolean strictWholeStringPool = false
    /** 安全默认值：启用后必须实际改写至少一个字符串和一个类。 */
    int minEncryptedStrings = 1
    int minModifiedClasses = 1
    int maxSkippedStrings = Integer.MAX_VALUE
    /** 超长或非法 Unicode 的未保护字符串默认不允许静默放行。 */
    int maxUnsafeSkippedStrings = 0
    /** custom shouldEncrypt/shouldFog 主动过滤默认不允许静默放行。 */
    int maxFilteredStrings = 0
    /** Release 默认要求可证明的全量覆盖；插件会为严格 variant 自动触发完整 ASM 访问。 */
    boolean failOnUnknownCoverage = true
    /** failOnUnknownCoverage 的 variant/buildType 过滤；默认只约束 release。 */
    List<String> failOnUnknownCoverageVariants = ['release']
    /** CFG 开启时，bridge/runtime decryptor 未命中 CFG 范围默认直接失败。 */
    boolean failOnUnprotectedDecryptor = true
    /** 自定义算法对象含运行时字段且未覆盖 toString 时，用该值显式参与 Gradle 输入摘要。 */
    String configurationId = ''
    String bridgeClass
    /**
     * application 最终 DEX 门禁还要聚合的 Android library project path（例如 ':feature'）。
     * library 必须对相同 variant 产出当前、FULL、member-scoped v6 evidence。
     */
    List<String> dependencyEvidenceProjects = []
    /** dependencyEvidenceProjects 的 variant/buildType 过滤；空表示所有 variant。 */
    List<String> dependencyEvidenceVariants = []

    void enable(boolean value) { enabled = value }
    void enabled(boolean value) { enabled = value }
    void enabledVariants(Object value) { enabledVariants = variantStrings(value) }
    void debug(boolean value) { debug = value }
    void implementation(String value) { implementation = value }
    void algorithm(Object value) { algorithm = value }
    void keyGenerator(Object value) { keyGenerator = value }
    void kg(Object value) { keyGenerator = value }
    Object getKg() { keyGenerator }
    void setKg(Object value) { keyGenerator = value }
    void mode(Object value) { mode = value }
    void packages(Object value) { packages = strings(value) }
    void fogPackages(Object value) { packages = strings(value) }
    List<String> getFogPackages() { packages }
    void setFogPackages(Object value) { packages = strings(value) }
    void excludePackages(Object value) { excludePackages = strings(value) }
    void maxStringBytes(int value) { maxStringBytes = value }
    void decryptorStatic(boolean value) { decryptorStatic = value }
    void verifyRoundTrip(boolean value) { verifyRoundTrip = value }
    void allowIdentityCiphertext(boolean value) { allowIdentityCiphertext = value }
    void failOnUnsupportedStringConstants(boolean value) { failOnUnsupportedStringConstants = value }
    void verifyFinalDex(boolean value) { verifyFinalDex = value }
    void failOnPlaintextLeak(boolean value) { failOnPlaintextLeak = value }
    void strictWholeStringPool(boolean value) { strictWholeStringPool = value }
    void minEncryptedStrings(int value) { minEncryptedStrings = value }
    void minModifiedClasses(int value) { minModifiedClasses = value }
    void maxSkippedStrings(int value) { maxSkippedStrings = value }
    void maxUnsafeSkippedStrings(int value) { maxUnsafeSkippedStrings = value }
    void maxFilteredStrings(int value) { maxFilteredStrings = value }
    void failOnUnknownCoverage(boolean value) { failOnUnknownCoverage = value }
    void failOnUnknownCoverageVariants(Object value) {
        failOnUnknownCoverageVariants = variantStrings(value)
    }
    void failOnUnprotectedDecryptor(boolean value) { failOnUnprotectedDecryptor = value }
    void configurationId(String value) { configurationId = value ?: '' }
    void bridgeClass(String value) { bridgeClass = value }
    void dependencyEvidenceProjects(Object value) { dependencyEvidenceProjects = strings(value) }
    void dependencyEvidenceVariants(Object value) {
        dependencyEvidenceVariants = variantStrings(value)
    }

    StringEncryptionMode resolvedMode() {
        StringEncryptionMode.from(mode)
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

    /** Preserve null entries so the selector validator fails instead of treating them as all variants. */
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
