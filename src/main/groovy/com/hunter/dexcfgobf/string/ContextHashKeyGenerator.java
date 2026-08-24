package com.hunter.dexcfgobf.string;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * 默认密钥生成器。对 seed、调用点和明文做 SHA-256，构建可复现且同一明文不会全局复用密钥。
 * 密钥最终仍会进入 APK，因此它用于字符串混淆，不应被当作秘密存储方案。
 */
public final class ContextHashKeyGenerator implements StringKeyGenerator {
    private final long seed;
    private final int length;

    public ContextHashKeyGenerator(long seed) {
        this(seed, 16);
    }

    public ContextHashKeyGenerator(long seed, int length) {
        if (length < 1 || length > 32) {
            throw new IllegalArgumentException("key length must be in [1, 32]");
        }
        this.seed = seed;
        this.length = length;
    }

    @Override
    public byte[] generate(String value, String location) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(ByteBuffer.allocate(Long.BYTES).putLong(seed).array());
            digest.update((byte) 0);
            digest.update(location.getBytes(StandardCharsets.UTF_8));
            digest.update((byte) 0);
            digest.update(value.getBytes(StandardCharsets.UTF_8));
            return Arrays.copyOf(digest.digest(), length);
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 unavailable", impossible);
        }
    }

    @Override
    public String toString() {
        return "ContextHashKeyGenerator/v1(seed=" + Long.toUnsignedString(seed)
                + ",length=" + length + ")";
    }
}
