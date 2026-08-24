package com.hunter.dexcfgobf.string;

/** Real javac LambdaMetafactory bytecode used to exercise structural call-site names. */
final class CompiledLambdaFixture {
    private CompiledLambdaFixture() {
    }

    static Runnable runnable() {
        return () -> { };
    }
}
