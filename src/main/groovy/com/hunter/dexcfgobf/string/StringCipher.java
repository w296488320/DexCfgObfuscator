package com.hunter.dexcfgobf.string;

/** 可选的构建期字符串加密 SPI。运行期解密由宿主实现类或内置桥完成。 */
public interface StringCipher {
    byte[] encrypt(String value, byte[] key);

    String decrypt(byte[] value, byte[] key);

    default boolean shouldEncrypt(String value) {
        return true;
    }
}
