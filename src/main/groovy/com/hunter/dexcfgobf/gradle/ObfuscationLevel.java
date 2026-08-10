package com.hunter.dexcfgobf.gradle;

/**
 * 面向宿主 DSL 的混淆等级。具体数值只在插件内部使用，避免宿主直接依赖实现细节。
 */
public enum ObfuscationLevel {
    /** 体积与构建速度优先。 */
    LOW(1),
    /** 默认等级，在复杂度、体积和 verifier 稳定性之间取平衡。 */
    MEDIUM(2),
    /** 更密集的切块和干扰状态，产物体积与构建耗时相应增加。 */
    HIGH(3);

    private final int depth;

    ObfuscationLevel(int depth) {
        this.depth = depth;
    }

    int getDepth() {
        return depth;
    }
}
