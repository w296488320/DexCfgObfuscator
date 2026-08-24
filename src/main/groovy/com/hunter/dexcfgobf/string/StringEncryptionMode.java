package com.hunter.dexcfgobf.string;

import java.util.Locale;

/** DEX 中密文/密钥的承载方式。 */
public enum StringEncryptionMode {
    /** 生成 byte[] 初始化指令；静态字符串池里不保留密文文本，但方法体会更大。 */
    BYTES,
    /** 以 Base64 String 常量承载密文；产物较小，运行时先解码。 */
    BASE64;

    // Groovy DSL 兼容 StringFogMode.bytes/base64/text 的小写写法。
    public static final StringEncryptionMode bytes = BYTES;
    public static final StringEncryptionMode base64 = BASE64;
    public static final StringEncryptionMode text = BASE64;

    public static StringEncryptionMode from(Object value) {
        if (value == null) return BYTES;
        if (value instanceof StringEncryptionMode) return (StringEncryptionMode) value;
        String name = value.toString().trim().toUpperCase(Locale.US);
        if (name.endsWith(".BYTES")) name = "BYTES";
        if (name.endsWith(".BASE64")) name = "BASE64";
        if (name.endsWith(".TEXT")) name = "TEXT";
        if ("TEXT".equals(name)) return BASE64;
        try {
            return valueOf(name);
        } catch (IllegalArgumentException badMode) {
            throw new IllegalArgumentException("unknown string encryption mode: " + value
                    + " (expected BYTES/base64/text)", badMode);
        }
    }
}
