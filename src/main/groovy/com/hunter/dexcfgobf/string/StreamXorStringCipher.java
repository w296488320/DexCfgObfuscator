package com.hunter.dexcfgobf.string;

import java.nio.charset.StandardCharsets;

/**
 * 无需宿主运行时依赖的默认可逆字节流混淆。它不是密码学加密；防护强度来自每调用点密钥、
 * R8 优化后的调用形态以及后续 DEX 控制流混淆的组合。
 */
public final class StreamXorStringCipher implements StringCipher {

    @Override
    public byte[] encrypt(String value, byte[] key) {
        return apply(value.getBytes(StandardCharsets.UTF_8), key);
    }

    @Override
    public String decrypt(byte[] value, byte[] key) {
        return new String(apply(value, key), StandardCharsets.UTF_8);
    }

    public static byte[] apply(byte[] input, byte[] key) {
        if (key == null || key.length == 0) {
            throw new IllegalArgumentException("built-in string cipher requires a non-empty key");
        }
        byte[] output = new byte[input.length];
        int state = 0x6D2B79F5;
        for (byte b : key) {
            state = (state * 33) ^ (b & 0xff);
        }
        for (int i = 0; i < input.length; i++) {
            state ^= state << 13;
            state ^= state >>> 17;
            state ^= state << 5;
            int mask = state & 0xff;
            if (mask == 0) mask = 0xA5;
            output[i] = (byte) (input[i] ^ mask);
        }
        return output;
    }

    public StreamXorStringCipher() {}

    @Override
    public String toString() {
        return "StreamXorStringCipher/v1";
    }
}
