package com.zhenxi.hunter.obfuscator;

/** 混淆统计，便于构建日志观测覆盖率与跳过原因。 */
public final class ObfuscatorStats {
    public int dexProcessed;
    public int dexFailed;
    public int classesScanned;
    public int methodsScanned;
    public int methodsObfuscated;
    public int methodsSkippedNotIncluded;
    public int methodsSkippedTryCatch;
    public int methodsSkippedTooSmall;
    public int methodsSkippedTooLarge;
    public int methodsSkippedUnsupported;

    @Override
    public String toString() {
        return "dexProcessed=" + dexProcessed
                + " dexFailed=" + dexFailed
                + " classesScanned=" + classesScanned
                + " methodsObfuscated=" + methodsObfuscated
                + " (scanned=" + methodsScanned
                + ", notIncluded=" + methodsSkippedNotIncluded
                + ", tryCatch=" + methodsSkippedTryCatch
                + ", tooSmall=" + methodsSkippedTooSmall
                + ", tooLarge=" + methodsSkippedTooLarge
                + ", unsupported=" + methodsSkippedUnsupported + ")";
    }
}
