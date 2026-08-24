package com.hunter.dexcfgobf.string;

/** 构建期密钥生成 SPI；location 可让相同明文在不同调用点得到不同密钥。 */
public interface StringKeyGenerator {
    byte[] generate(String value, String location);
}
