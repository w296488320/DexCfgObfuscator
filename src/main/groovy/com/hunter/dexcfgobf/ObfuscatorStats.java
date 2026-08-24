package com.hunter.dexcfgobf;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

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
    /** R8 exact-scope diagnostics; member-only owners avoid transforming unrelated host methods. */
    public int cfgResolvedClassWideOwners;
    public int cfgResolvedMemberOnlyOwners;
    public int cfgResolvedMemberMethods;
    public int cfgRequiredMethodsResolved;
    public int cfgRequiredMethodsScanned;
    public int cfgRequiredMethodsObfuscated;
    public int switchesPadded;
    public int switchCasesBefore;
    public int switchCasesAfter;
    public int fakeSwitchCases;
    public int symbolSwitchCases;
    public int regionalDispatchers;
    public int reachableAliasCases;
    public int stateSharedMethods;
    public boolean stringEncryptionEnabled;
    public String stringEncryptionMode = "DISABLED";
    public String stringCoverageStatus = "DISABLED";
    public int stringClassesVisited;
    public int stringClassesModified;
    public int stringConstantsEncrypted;
    public int stringConstantsSkipped;
    public int stringSkippedWhitespace;
    public int stringSkippedTooLarge;
    public int stringSkippedInvalidUnicode;
    public int stringSkippedFiltered;
    public int stringUnsupportedConstants;
    public int stringIdentityCiphertexts;
    public boolean stringPlaintextVerified;
    public int stringDexFilesScanned;
    public int stringPoolEntriesScanned;
    public int stringPlaintextHashesTracked;
    /** Application/library runtime-payload or strict-whole-pool mode; MIXED after aggregation. */
    public String stringPlaintextGateMode = "DISABLED";
    public int stringPlaintextLeaks;
    public int stringPlaintextLeakOccurrences;
    /** Legacy alias of the exact-site runtime gate result. */
    public int stringRuntimePlaintextLeaks;
    public int stringRuntimePlaintextLeakOccurrences;
    /** Executable payload hashes found at the exact mapped method/field site. */
    public int stringScopedRuntimePlaintextLeaks;
    public int stringScopedRuntimePlaintextLeakOccurrences;
    /** R8-unresolved site hashes protected by the fail-closed global runtime payload fallback. */
    public int stringGlobalRuntimeFallbackHashesTracked;
    public int stringGlobalRuntimeFallbackPlaintextLeaks;
    public int stringGlobalRuntimeFallbackPlaintextLeakOccurrences;
    /** Same-value runtime payloads inside a target final owner; diagnostic only. */
    public int stringOwnerRuntimePlaintextCollisions;
    public int stringOwnerRuntimePlaintextCollisionOccurrences;
    /** Same-value runtime payloads anywhere in the final DEX; diagnostic only outside strict mode. */
    public int stringGlobalRuntimePlaintextCollisions;
    public int stringGlobalRuntimePlaintextCollisionOccurrences;
    public int stringWholePoolPlaintextCollisions;
    public int stringWholePoolPlaintextCollisionOccurrences;
    /** Exact final owner names produced directly or through R8 mapping, and owners present in DEX. */
    public int stringTargetClassesResolved;
    public int stringTargetClassesScanned;
    public int stringTargetMethodsResolved;
    public int stringTargetMethodsScanned;
    public int stringTargetFieldsResolved;
    public int stringTargetFieldsScanned;
    /** R8 final-string-site classification; counts contain no member names or value hashes. */
    public int stringR8MappedMethodSites;
    public int stringR8RemovedMethodSites;
    public int stringR8IdentityMethodSites;
    public int stringR8FallbackMethodSites;
    public int stringR8MappedFieldProvenance;
    public int stringR8RemovedFieldProvenance;
    public int stringR8IdentityFieldProvenance;
    public int stringR8FallbackFieldProvenance;
    public int stringRemovedOriginalSiteHashesTracked;
    public int stringIdentityFieldProvenanceResolved;
    public int stringIdentityFieldProvenanceScanned;
    public int stringConstStringReferencesScanned;
    public int stringStaticStringValuesScanned;
    public int stringAnnotationStringValuesScanned;
    public int stringCallSiteStringValuesScanned;
    public int stringStructuralAnnotationStringValuesScanned;
    public int stringStructuralAnnotationPlaintextCollisions;
    public int stringStructuralAnnotationPlaintextCollisionOccurrences;
    public int stringMinEncryptedStrings;
    public int stringMinModifiedClasses;
    public int stringMaxSkippedStrings = Integer.MAX_VALUE;
    public int stringMaxUnsafeSkippedStrings = Integer.MAX_VALUE;
    public int stringMaxFilteredStrings = Integer.MAX_VALUE;
    public boolean stringFailOnUnknownCoverage;
    public boolean stringVerifyFinalDex;
    public boolean stringFailOnPlaintextLeak;
    public boolean stringFailOnUnsupportedConstants;
    public boolean stringFailOnUnprotectedDecryptor;
    /** 与报告/证据绑定的最终 DEX 与变换配置摘要；不包含业务明文。 */
    public String artifactFingerprint = "";
    public String cfgTransformDigest = "";
    public String stringTransformDigest = "";
    public String evidenceSource = "CURRENT_BUILD";
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

    /** Every residual overload at every required final owner->name must be seen and transformed. */
    public boolean hasCompleteRequiredMethodCoverage(Set<String> requiredFinalMethods) {
        if (requiredFinalMethods == null || requiredFinalMethods.isEmpty()) return false;
        Map<String, Integer> scanned = new HashMap<>();
        Map<String, Integer> obfuscated = new HashMap<>();
        for (MethodReport report : methodReports) {
            String key = ObfuscatorConfig.normalizeClassName(report.owner) + "->" + report.name;
            if (!requiredFinalMethods.contains(key)) continue;
            scanned.put(key, scanned.getOrDefault(key, 0) + 1);
            if (!"skipped".equals(report.mode)) {
                obfuscated.put(key, obfuscated.getOrDefault(key, 0) + 1);
            }
        }
        for (String required : requiredFinalMethods) {
            int seen = scanned.getOrDefault(required, 0);
            if (seen == 0 || obfuscated.getOrDefault(required, 0) != seen) return false;
        }
        return true;
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
        cfgResolvedClassWideOwners += other.cfgResolvedClassWideOwners;
        cfgResolvedMemberOnlyOwners += other.cfgResolvedMemberOnlyOwners;
        cfgResolvedMemberMethods += other.cfgResolvedMemberMethods;
        cfgRequiredMethodsResolved += other.cfgRequiredMethodsResolved;
        cfgRequiredMethodsScanned += other.cfgRequiredMethodsScanned;
        cfgRequiredMethodsObfuscated += other.cfgRequiredMethodsObfuscated;
        switchesPadded += other.switchesPadded;
        switchCasesBefore += other.switchCasesBefore;
        switchCasesAfter += other.switchCasesAfter;
        fakeSwitchCases += other.fakeSwitchCases;
        symbolSwitchCases += other.symbolSwitchCases;
        regionalDispatchers += other.regionalDispatchers;
        reachableAliasCases += other.reachableAliasCases;
        stateSharedMethods += other.stateSharedMethods;
        stringEncryptionEnabled |= other.stringEncryptionEnabled;
        if (other.stringEncryptionEnabled) stringEncryptionMode = other.stringEncryptionMode;
        if (!"DISABLED".equals(other.stringCoverageStatus)) {
            stringCoverageStatus = other.stringCoverageStatus;
        }
        if (other.stringTransformDigest != null && !other.stringTransformDigest.isEmpty()) {
            stringTransformDigest = other.stringTransformDigest;
        }
        stringClassesVisited += other.stringClassesVisited;
        stringClassesModified += other.stringClassesModified;
        stringConstantsEncrypted += other.stringConstantsEncrypted;
        stringConstantsSkipped += other.stringConstantsSkipped;
        stringSkippedWhitespace += other.stringSkippedWhitespace;
        stringSkippedTooLarge += other.stringSkippedTooLarge;
        stringSkippedInvalidUnicode += other.stringSkippedInvalidUnicode;
        stringSkippedFiltered += other.stringSkippedFiltered;
        stringUnsupportedConstants += other.stringUnsupportedConstants;
        stringIdentityCiphertexts += other.stringIdentityCiphertexts;
        boolean hadStringVerification = stringPlaintextVerified;
        if (other.stringPlaintextVerified) {
            if (!hadStringVerification || "DISABLED".equals(stringPlaintextGateMode)) {
                stringPlaintextGateMode = other.stringPlaintextGateMode;
            } else if (!stringPlaintextGateMode.equals(other.stringPlaintextGateMode)) {
                stringPlaintextGateMode = "MIXED";
            }
        }
        stringPlaintextVerified |= other.stringPlaintextVerified;
        stringDexFilesScanned += other.stringDexFilesScanned;
        stringPoolEntriesScanned += other.stringPoolEntriesScanned;
        stringPlaintextHashesTracked += other.stringPlaintextHashesTracked;
        stringPlaintextLeaks += other.stringPlaintextLeaks;
        stringPlaintextLeakOccurrences += other.stringPlaintextLeakOccurrences;
        stringRuntimePlaintextLeaks += other.stringRuntimePlaintextLeaks;
        stringRuntimePlaintextLeakOccurrences += other.stringRuntimePlaintextLeakOccurrences;
        stringScopedRuntimePlaintextLeaks += other.stringScopedRuntimePlaintextLeaks;
        stringScopedRuntimePlaintextLeakOccurrences +=
                other.stringScopedRuntimePlaintextLeakOccurrences;
        stringGlobalRuntimeFallbackHashesTracked +=
                other.stringGlobalRuntimeFallbackHashesTracked;
        stringGlobalRuntimeFallbackPlaintextLeaks +=
                other.stringGlobalRuntimeFallbackPlaintextLeaks;
        stringGlobalRuntimeFallbackPlaintextLeakOccurrences +=
                other.stringGlobalRuntimeFallbackPlaintextLeakOccurrences;
        stringOwnerRuntimePlaintextCollisions += other.stringOwnerRuntimePlaintextCollisions;
        stringOwnerRuntimePlaintextCollisionOccurrences +=
                other.stringOwnerRuntimePlaintextCollisionOccurrences;
        stringGlobalRuntimePlaintextCollisions += other.stringGlobalRuntimePlaintextCollisions;
        stringGlobalRuntimePlaintextCollisionOccurrences +=
                other.stringGlobalRuntimePlaintextCollisionOccurrences;
        stringWholePoolPlaintextCollisions += other.stringWholePoolPlaintextCollisions;
        stringWholePoolPlaintextCollisionOccurrences +=
                other.stringWholePoolPlaintextCollisionOccurrences;
        stringTargetClassesResolved += other.stringTargetClassesResolved;
        stringTargetClassesScanned += other.stringTargetClassesScanned;
        stringTargetMethodsResolved += other.stringTargetMethodsResolved;
        stringTargetMethodsScanned += other.stringTargetMethodsScanned;
        stringTargetFieldsResolved += other.stringTargetFieldsResolved;
        stringTargetFieldsScanned += other.stringTargetFieldsScanned;
        stringR8MappedMethodSites += other.stringR8MappedMethodSites;
        stringR8RemovedMethodSites += other.stringR8RemovedMethodSites;
        stringR8IdentityMethodSites += other.stringR8IdentityMethodSites;
        stringR8FallbackMethodSites += other.stringR8FallbackMethodSites;
        stringR8MappedFieldProvenance += other.stringR8MappedFieldProvenance;
        stringR8RemovedFieldProvenance += other.stringR8RemovedFieldProvenance;
        stringR8IdentityFieldProvenance += other.stringR8IdentityFieldProvenance;
        stringR8FallbackFieldProvenance += other.stringR8FallbackFieldProvenance;
        stringRemovedOriginalSiteHashesTracked +=
                other.stringRemovedOriginalSiteHashesTracked;
        stringIdentityFieldProvenanceResolved +=
                other.stringIdentityFieldProvenanceResolved;
        stringIdentityFieldProvenanceScanned +=
                other.stringIdentityFieldProvenanceScanned;
        stringConstStringReferencesScanned += other.stringConstStringReferencesScanned;
        stringStaticStringValuesScanned += other.stringStaticStringValuesScanned;
        stringAnnotationStringValuesScanned += other.stringAnnotationStringValuesScanned;
        stringCallSiteStringValuesScanned += other.stringCallSiteStringValuesScanned;
        stringStructuralAnnotationStringValuesScanned +=
                other.stringStructuralAnnotationStringValuesScanned;
        stringStructuralAnnotationPlaintextCollisions +=
                other.stringStructuralAnnotationPlaintextCollisions;
        stringStructuralAnnotationPlaintextCollisionOccurrences +=
                other.stringStructuralAnnotationPlaintextCollisionOccurrences;
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
