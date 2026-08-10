package com.hunter.dexcfgobf;

/** 极简日志抽象，避免 buildSrc 直接依赖 Gradle Logger 便于单元测试。 */
public interface ObfuscatorLogger {
    void info(String message);
    void warn(String message);

    /** 输出到标准输出的默认实现，供单元测试/命令行使用。 */
    ObfuscatorLogger STDOUT = new ObfuscatorLogger() {
        @Override
        public void info(String message) {
            System.out.println("[cfg-obf] " + message);
        }

        @Override
        public void warn(String message) {
            System.out.println("[cfg-obf][WARN] " + message);
        }
    };
}
