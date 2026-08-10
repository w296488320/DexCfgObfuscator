package com.hunter.dexcfgobf;

import java.util.ArrayList;
import java.util.List;

/** 混淆统计，便于构建日志观测覆盖率与跳过原因。 */
public final class ObfuscatorStats {
    public int dexProcessed;
    public int dexVerified;
    public int dexFailed;
    public int classesScanned;
    public int methodsScanned;
    public int methodsObfuscated;
    public int methodsFlattened;   // 走控制流平坦化（强）
    public int methodsReordered;   // 走基本块重排（弱，含 try/catch 方法）
    public int reorderedTryCatch;  // 因 try/catch 回退重排
    public int reorderedRegConflict; // 因寄存器 wide/narrow 冲突回退重排
    public int reorderedVerifierRisk; // 对象/数组/invoke/非静态等 verifier 风险回退重排
    public int methodsSkippedNotIncluded;
    public int methodsSkippedTryCatch;
    public int methodsSkippedTooSmall;
    public int methodsSkippedTooLarge;
    public int methodsSkippedUnsupported;
    public int methodsSkippedAlreadyObfuscated;
    public int methodsSkippedVerifierAnalysis;
    public int methodsSkippedRegisterBudget;
    public int switchesPadded;
    public int switchCasesBefore;
    public int switchCasesAfter;
    public int fakeSwitchCases;
    public int symbolSwitchCases;
    public int regionalDispatchers;
    public int reachableAliasCases;
    public int stateSharedMethods;
    public long originalDexBytes;
    public long outputDexBytes;
    public final List<MethodReport> methodReports = new ArrayList<>();

    void recordOutcome(TransformationOutcome outcome) {
        switchesPadded += outcome.switchesPadded;
        switchCasesBefore += outcome.switchCasesBefore;
        switchCasesAfter += outcome.switchCasesAfter;
        fakeSwitchCases += outcome.fakeSwitchCases;
        symbolSwitchCases += outcome.symbolSwitchCases;
        regionalDispatchers += outcome.dispatcherRegions;
        reachableAliasCases += outcome.reachableAliasCases;
        if (outcome.stateShareRegisters >= 2) stateSharedMethods++;
        switch (outcome.mode) {
            case FLATTENED:
                methodsFlattened++;
                break;
            case REORDERED:
                methodsReordered++;
                if (outcome.reason == TransformationOutcome.Reason.TRY_CATCH_REORDER) reorderedTryCatch++;
                if (outcome.reason == TransformationOutcome.Reason.VERIFIER_RISK_REORDER
                        || outcome.reason == TransformationOutcome.Reason.FLATTEN_FALLBACK_REORDER) {
                    reorderedVerifierRisk++;
                }
                break;
            case SKIPPED:
                switch (outcome.reason) {
                    case ALREADY_OBFUSCATED: methodsSkippedAlreadyObfuscated++; break;
                    case TRY_CATCH_DISABLED: methodsSkippedTryCatch++; break;
                    case TOO_SMALL: methodsSkippedTooSmall++; break;
                    case TOO_LARGE: methodsSkippedTooLarge++; break;
                    case REGISTER_BUDGET: methodsSkippedRegisterBudget++; break;
                    case VERIFIER_ANALYSIS_FAILED: methodsSkippedVerifierAnalysis++; break;
                    default: methodsSkippedUnsupported++; break;
                }
                break;
        }
    }

    public int methodsSkipped() {
        return methodsSkippedTryCatch + methodsSkippedTooSmall + methodsSkippedTooLarge
                + methodsSkippedUnsupported + methodsSkippedAlreadyObfuscated
                + methodsSkippedVerifierAnalysis + methodsSkippedRegisterBudget;
    }

    public double sizeIncreasePercent() {
        if (originalDexBytes <= 0L) return 0.0d;
        return ((double) outputDexBytes - originalDexBytes) * 100.0d / originalDexBytes;
    }

    public double obfuscatedRatio() {
        return methodsScanned == 0 ? 0.0d : (double) methodsObfuscated / methodsScanned;
    }

    public void mergeFrom(ObfuscatorStats other) {
        dexProcessed += other.dexProcessed;
        dexVerified += other.dexVerified;
        dexFailed += other.dexFailed;
        classesScanned += other.classesScanned;
        methodsScanned += other.methodsScanned;
        methodsObfuscated += other.methodsObfuscated;
        methodsFlattened += other.methodsFlattened;
        methodsReordered += other.methodsReordered;
        reorderedTryCatch += other.reorderedTryCatch;
        reorderedRegConflict += other.reorderedRegConflict;
        reorderedVerifierRisk += other.reorderedVerifierRisk;
        methodsSkippedNotIncluded += other.methodsSkippedNotIncluded;
        methodsSkippedTryCatch += other.methodsSkippedTryCatch;
        methodsSkippedTooSmall += other.methodsSkippedTooSmall;
        methodsSkippedTooLarge += other.methodsSkippedTooLarge;
        methodsSkippedUnsupported += other.methodsSkippedUnsupported;
        methodsSkippedAlreadyObfuscated += other.methodsSkippedAlreadyObfuscated;
        methodsSkippedVerifierAnalysis += other.methodsSkippedVerifierAnalysis;
        methodsSkippedRegisterBudget += other.methodsSkippedRegisterBudget;
        switchesPadded += other.switchesPadded;
        switchCasesBefore += other.switchCasesBefore;
        switchCasesAfter += other.switchCasesAfter;
        fakeSwitchCases += other.fakeSwitchCases;
        symbolSwitchCases += other.symbolSwitchCases;
        regionalDispatchers += other.regionalDispatchers;
        reachableAliasCases += other.reachableAliasCases;
        stateSharedMethods += other.stateSharedMethods;
        originalDexBytes += other.originalDexBytes;
        outputDexBytes += other.outputDexBytes;
        methodReports.addAll(other.methodReports);
    }

    @Override
    public String toString() {
        return "dexProcessed=" + dexProcessed
                + " dexVerified=" + dexVerified
                + " dexFailed=" + dexFailed
                + " classesScanned=" + classesScanned
                + " methodsObfuscated=" + methodsObfuscated
                + " (flattened=" + methodsFlattened
                + ", reordered=" + methodsReordered
                + " [tryCatch=" + reorderedTryCatch + ", verifierRisk=" + reorderedVerifierRisk
                + ", regConflict=" + reorderedRegConflict + "]"
                + ", scanned=" + methodsScanned
                + ", notIncluded=" + methodsSkippedNotIncluded
                + ", tryCatch=" + methodsSkippedTryCatch
                + ", tooSmall=" + methodsSkippedTooSmall
                + ", tooLarge=" + methodsSkippedTooLarge
                + ", alreadyObfuscated=" + methodsSkippedAlreadyObfuscated
                + ", verifierAnalysis=" + methodsSkippedVerifierAnalysis
                + ", registerBudget=" + methodsSkippedRegisterBudget
                + ", unsupported=" + methodsSkippedUnsupported
                + ", switchPadding=" + switchesPadded
                + " [cases=" + switchCasesBefore + "->" + switchCasesAfter
                + ", fake=" + fakeSwitchCases + ", symbol=" + symbolSwitchCases + "]"
                + ", regionalDispatchers=" + regionalDispatchers
                + ", reachableAliases=" + reachableAliasCases
                + ", stateSharedMethods=" + stateSharedMethods + ")";
    }
}
