package com.hunter.dexcfgobf;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;

/** 无额外 JSON 依赖的稳定报告写入器。 */
public final class ObfuscationReportWriter {
    private ObfuscationReportWriter() {}

    public static void write(File file, String variant, ObfuscatorConfig config,
                             ObfuscatorStats stats) throws java.io.IOException {
        File parent = file.getParentFile();
        if (parent != null && !parent.isDirectory() && !parent.mkdirs() && !parent.isDirectory()) {
            throw new java.io.IOException("cannot create report directory: " + parent);
        }
        try (BufferedWriter out = new BufferedWriter(new OutputStreamWriter(
                new FileOutputStream(file), StandardCharsets.UTF_8))) {
            out.write("{\n");
            field(out, "schemaVersion", "10", false, 1);
            field(out, "variant", quote(variant), false, 1);
            field(out, "seed", quote(Long.toUnsignedString(config.seed)), false, 1);
            out.write("  \"evidence\": {\n");
            field(out, "source", quote(stats.evidenceSource), false, 2);
            field(out, "artifactFingerprint", quote(stats.artifactFingerprint), false, 2);
            field(out, "cfgTransformDigest", quote(stats.cfgTransformDigest), false, 2);
            field(out, "stringTransformDigest", quote(stats.stringTransformDigest), true, 2);
            out.write("  },\n");
            out.write("  \"summary\": {\n");
            field(out, "dexProcessed", Integer.toString(stats.dexProcessed), false, 2);
            field(out, "dexVerified", Integer.toString(stats.dexVerified), false, 2);
            field(out, "dexFailed", Integer.toString(stats.dexFailed), false, 2);
            field(out, "classesScanned", Integer.toString(stats.classesScanned), false, 2);
            field(out, "methodsScanned", Integer.toString(stats.methodsScanned), false, 2);
            field(out, "methodsObfuscated", Integer.toString(stats.methodsObfuscated), false, 2);
            field(out, "methodsFlattened", Integer.toString(stats.methodsFlattened), false, 2);
            field(out, "methodsReordered", Integer.toString(stats.methodsReordered), false, 2);
            field(out, "methodsSkipped", Integer.toString(stats.methodsSkipped()), false, 2);
            field(out, "cfgResolvedClassWideOwners", Integer.toString(stats.cfgResolvedClassWideOwners), false, 2);
            field(out, "cfgResolvedMemberOnlyOwners", Integer.toString(stats.cfgResolvedMemberOnlyOwners), false, 2);
            field(out, "cfgResolvedMemberMethods", Integer.toString(stats.cfgResolvedMemberMethods), false, 2);
            field(out, "cfgRequiredMethodsResolved", Integer.toString(stats.cfgRequiredMethodsResolved), false, 2);
            field(out, "cfgRequiredMethodsScanned", Integer.toString(stats.cfgRequiredMethodsScanned), false, 2);
            field(out, "cfgRequiredMethodsObfuscated", Integer.toString(stats.cfgRequiredMethodsObfuscated), false, 2);
            field(out, "switchesPadded", Integer.toString(stats.switchesPadded), false, 2);
            field(out, "switchCasesBefore", Integer.toString(stats.switchCasesBefore), false, 2);
            field(out, "switchCasesAfter", Integer.toString(stats.switchCasesAfter), false, 2);
            field(out, "fakeSwitchCases", Integer.toString(stats.fakeSwitchCases), false, 2);
            field(out, "symbolSwitchCases", Integer.toString(stats.symbolSwitchCases), false, 2);
            field(out, "regionalDispatchers", Integer.toString(stats.regionalDispatchers), false, 2);
            field(out, "reachableAliasCases", Integer.toString(stats.reachableAliasCases), false, 2);
            field(out, "stateSharedMethods", Integer.toString(stats.stateSharedMethods), false, 2);
            field(out, "stringEncryptionEnabled", Boolean.toString(stats.stringEncryptionEnabled), false, 2);
            field(out, "stringEncryptionMode", quote(stats.stringEncryptionMode), false, 2);
            field(out, "stringCoverageStatus", quote(stats.stringCoverageStatus), false, 2);
            field(out, "stringClassesVisited", Integer.toString(stats.stringClassesVisited), false, 2);
            field(out, "stringClassesModified", Integer.toString(stats.stringClassesModified), false, 2);
            field(out, "stringConstantsEncrypted", Integer.toString(stats.stringConstantsEncrypted), false, 2);
            field(out, "stringConstantsSkipped", Integer.toString(stats.stringConstantsSkipped), false, 2);
            field(out, "stringSkippedWhitespace", Integer.toString(stats.stringSkippedWhitespace), false, 2);
            field(out, "stringSkippedTooLarge", Integer.toString(stats.stringSkippedTooLarge), false, 2);
            field(out, "stringSkippedInvalidUnicode", Integer.toString(stats.stringSkippedInvalidUnicode), false, 2);
            field(out, "stringSkippedFiltered", Integer.toString(stats.stringSkippedFiltered), false, 2);
            field(out, "stringUnsupportedConstants", Integer.toString(stats.stringUnsupportedConstants), false, 2);
            field(out, "stringIdentityCiphertexts", Integer.toString(stats.stringIdentityCiphertexts), false, 2);
            field(out, "stringPlaintextVerified", Boolean.toString(stats.stringPlaintextVerified), false, 2);
            field(out, "stringDexFilesScanned", Integer.toString(stats.stringDexFilesScanned), false, 2);
            field(out, "stringPoolEntriesScanned", Integer.toString(stats.stringPoolEntriesScanned), false, 2);
            field(out, "stringPlaintextHashesTracked", Integer.toString(stats.stringPlaintextHashesTracked), false, 2);
            field(out, "stringPlaintextGateMode", quote(stats.stringPlaintextGateMode), false, 2);
            field(out, "stringPlaintextLeaks", Integer.toString(stats.stringPlaintextLeaks), false, 2);
            field(out, "stringPlaintextLeakOccurrences", Integer.toString(stats.stringPlaintextLeakOccurrences), false, 2);
            field(out, "stringRuntimePlaintextLeaks", Integer.toString(stats.stringRuntimePlaintextLeaks), false, 2);
            field(out, "stringRuntimePlaintextLeakOccurrences", Integer.toString(stats.stringRuntimePlaintextLeakOccurrences), false, 2);
            field(out, "stringScopedRuntimePlaintextLeaks", Integer.toString(stats.stringScopedRuntimePlaintextLeaks), false, 2);
            field(out, "stringScopedRuntimePlaintextLeakOccurrences", Integer.toString(stats.stringScopedRuntimePlaintextLeakOccurrences), false, 2);
            field(out, "stringGlobalRuntimeFallbackHashesTracked", Integer.toString(stats.stringGlobalRuntimeFallbackHashesTracked), false, 2);
            field(out, "stringGlobalRuntimeFallbackPlaintextLeaks", Integer.toString(stats.stringGlobalRuntimeFallbackPlaintextLeaks), false, 2);
            field(out, "stringGlobalRuntimeFallbackPlaintextLeakOccurrences", Integer.toString(stats.stringGlobalRuntimeFallbackPlaintextLeakOccurrences), false, 2);
            field(out, "stringOwnerRuntimePlaintextCollisions", Integer.toString(stats.stringOwnerRuntimePlaintextCollisions), false, 2);
            field(out, "stringOwnerRuntimePlaintextCollisionOccurrences", Integer.toString(stats.stringOwnerRuntimePlaintextCollisionOccurrences), false, 2);
            field(out, "stringGlobalRuntimePlaintextCollisions", Integer.toString(stats.stringGlobalRuntimePlaintextCollisions), false, 2);
            field(out, "stringGlobalRuntimePlaintextCollisionOccurrences", Integer.toString(stats.stringGlobalRuntimePlaintextCollisionOccurrences), false, 2);
            field(out, "stringWholePoolPlaintextCollisions", Integer.toString(stats.stringWholePoolPlaintextCollisions), false, 2);
            field(out, "stringWholePoolPlaintextCollisionOccurrences", Integer.toString(stats.stringWholePoolPlaintextCollisionOccurrences), false, 2);
            field(out, "stringTargetClassesResolved", Integer.toString(stats.stringTargetClassesResolved), false, 2);
            field(out, "stringTargetClassesScanned", Integer.toString(stats.stringTargetClassesScanned), false, 2);
            field(out, "stringTargetMethodsResolved", Integer.toString(stats.stringTargetMethodsResolved), false, 2);
            field(out, "stringTargetMethodsScanned", Integer.toString(stats.stringTargetMethodsScanned), false, 2);
            field(out, "stringTargetFieldsResolved", Integer.toString(stats.stringTargetFieldsResolved), false, 2);
            field(out, "stringTargetFieldsScanned", Integer.toString(stats.stringTargetFieldsScanned), false, 2);
            field(out, "stringR8MappedMethodSites", Integer.toString(stats.stringR8MappedMethodSites), false, 2);
            field(out, "stringR8RemovedMethodSites", Integer.toString(stats.stringR8RemovedMethodSites), false, 2);
            field(out, "stringR8IdentityMethodSites", Integer.toString(stats.stringR8IdentityMethodSites), false, 2);
            field(out, "stringR8FallbackMethodSites", Integer.toString(stats.stringR8FallbackMethodSites), false, 2);
            field(out, "stringR8MappedFieldProvenance", Integer.toString(stats.stringR8MappedFieldProvenance), false, 2);
            field(out, "stringR8RemovedFieldProvenance", Integer.toString(stats.stringR8RemovedFieldProvenance), false, 2);
            field(out, "stringR8IdentityFieldProvenance", Integer.toString(stats.stringR8IdentityFieldProvenance), false, 2);
            field(out, "stringR8FallbackFieldProvenance", Integer.toString(stats.stringR8FallbackFieldProvenance), false, 2);
            field(out, "stringRemovedOriginalSiteHashesTracked", Integer.toString(stats.stringRemovedOriginalSiteHashesTracked), false, 2);
            field(out, "stringIdentityFieldProvenanceResolved", Integer.toString(stats.stringIdentityFieldProvenanceResolved), false, 2);
            field(out, "stringIdentityFieldProvenanceScanned", Integer.toString(stats.stringIdentityFieldProvenanceScanned), false, 2);
            field(out, "stringConstStringReferencesScanned", Integer.toString(stats.stringConstStringReferencesScanned), false, 2);
            field(out, "stringStaticStringValuesScanned", Integer.toString(stats.stringStaticStringValuesScanned), false, 2);
            field(out, "stringAnnotationStringValuesScanned", Integer.toString(stats.stringAnnotationStringValuesScanned), false, 2);
            field(out, "stringCallSiteStringValuesScanned", Integer.toString(stats.stringCallSiteStringValuesScanned), false, 2);
            field(out, "stringStructuralAnnotationStringValuesScanned", Integer.toString(stats.stringStructuralAnnotationStringValuesScanned), false, 2);
            field(out, "stringStructuralAnnotationPlaintextCollisions", Integer.toString(stats.stringStructuralAnnotationPlaintextCollisions), false, 2);
            field(out, "stringStructuralAnnotationPlaintextCollisionOccurrences", Integer.toString(stats.stringStructuralAnnotationPlaintextCollisionOccurrences), false, 2);
            field(out, "obfuscatedRatio", Double.toString(stats.obfuscatedRatio()), false, 2);
            field(out, "originalDexBytes", Long.toString(stats.originalDexBytes), false, 2);
            field(out, "outputDexBytes", Long.toString(stats.outputDexBytes), false, 2);
            field(out, "sizeIncreasePercent", Double.toString(stats.sizeIncreasePercent()), true, 2);
            out.write("  },\n");
            out.write("  \"skipReasons\": {\n");
            field(out, "notIncluded", Integer.toString(stats.methodsSkippedNotIncluded), false, 2);
            field(out, "tryCatchDisabled", Integer.toString(stats.methodsSkippedTryCatch), false, 2);
            field(out, "tooSmall", Integer.toString(stats.methodsSkippedTooSmall), false, 2);
            field(out, "tooLarge", Integer.toString(stats.methodsSkippedTooLarge), false, 2);
            field(out, "alreadyObfuscated", Integer.toString(stats.methodsSkippedAlreadyObfuscated), false, 2);
            field(out, "verifierAnalysis", Integer.toString(stats.methodsSkippedVerifierAnalysis), false, 2);
            field(out, "registerBudget", Integer.toString(stats.methodsSkippedRegisterBudget), false, 2);
            field(out, "unsupported", Integer.toString(stats.methodsSkippedUnsupported), true, 2);
            out.write("  },\n");
            out.write("  \"budgets\": {\n");
            field(out, "minObfuscatedMethods", Integer.toString(config.minObfuscatedMethods), false, 2);
            field(out, "minFlattenedMethods", Integer.toString(config.minFlattenedMethods), false, 2);
            field(out, "minObfuscatedRatio", Double.toString(config.minObfuscatedRatio), false, 2);
            field(out, "maxSizeIncreasePercent", Double.toString(config.maxSizeIncreasePercent), false, 2);
            field(out, "minEncryptedStrings", Integer.toString(stats.stringMinEncryptedStrings), false, 2);
            field(out, "minModifiedStringClasses", Integer.toString(stats.stringMinModifiedClasses), false, 2);
            field(out, "maxSkippedStrings", Integer.toString(stats.stringMaxSkippedStrings), false, 2);
            field(out, "maxUnsafeSkippedStrings", Integer.toString(stats.stringMaxUnsafeSkippedStrings), false, 2);
            field(out, "maxFilteredStrings", Integer.toString(stats.stringMaxFilteredStrings), false, 2);
            field(out, "failOnUnknownStringCoverage", Boolean.toString(stats.stringFailOnUnknownCoverage), false, 2);
            field(out, "verifyFinalDex", Boolean.toString(stats.stringVerifyFinalDex), false, 2);
            field(out, "failOnPlaintextLeak", Boolean.toString(stats.stringFailOnPlaintextLeak), false, 2);
            field(out, "failOnUnsupportedStringConstants", Boolean.toString(stats.stringFailOnUnsupportedConstants), false, 2);
            field(out, "failOnUnprotectedDecryptor", Boolean.toString(stats.stringFailOnUnprotectedDecryptor), true, 2);
            out.write("  },\n");
            out.write("  \"methods\": [\n");
            for (int i = 0; i < stats.methodReports.size(); i++) {
                MethodReport r = stats.methodReports.get(i);
                out.write("    {\n");
                field(out, "dex", quote(r.dex), false, 3);
                field(out, "owner", quote(r.owner), false, 3);
                field(out, "name", quote(r.name), false, 3);
                field(out, "descriptor", quote(r.descriptor), false, 3);
                field(out, "mode", quote(r.mode), false, 3);
                field(out, "reason", quote(r.reason), false, 3);
                field(out, "template", quote(r.template), false, 3);
                field(out, "instructionsBefore", Integer.toString(r.instructionsBefore), false, 3);
                field(out, "instructionsAfter", Integer.toString(r.instructionsAfter), false, 3);
                field(out, "codeUnitsBefore", Integer.toString(r.codeUnitsBefore), false, 3);
                field(out, "codeUnitsAfter", Integer.toString(r.codeUnitsAfter), false, 3);
                field(out, "registersBefore", Integer.toString(r.registersBefore), false, 3);
                field(out, "registersAfter", Integer.toString(r.registersAfter), false, 3);
                field(out, "hasTry", Boolean.toString(r.hasTry), false, 3);
                field(out, "hasSwitch", Boolean.toString(r.hasSwitch), false, 3);
                field(out, "hasArrayPayload", Boolean.toString(r.hasArrayPayload), false, 3);
                field(out, "registerTypesSeparated", Boolean.toString(r.registerTypesSeparated), false, 3);
                field(out, "addedRegisters", Integer.toString(r.addedRegisters), false, 3);
                field(out, "switchesPadded", Integer.toString(r.switchesPadded), false, 3);
                field(out, "switchCasesBefore", Integer.toString(r.switchCasesBefore), false, 3);
                field(out, "switchCasesAfter", Integer.toString(r.switchCasesAfter), false, 3);
                field(out, "fakeSwitchCases", Integer.toString(r.fakeSwitchCases), false, 3);
                field(out, "symbolSwitchCases", Integer.toString(r.symbolSwitchCases), false, 3);
                field(out, "dispatcherRegions", Integer.toString(r.dispatcherRegions), false, 3);
                field(out, "reachableAliasCases", Integer.toString(r.reachableAliasCases), false, 3);
                field(out, "stateShareRegisters", Integer.toString(r.stateShareRegisters), true, 3);
                out.write("    }" + (i + 1 == stats.methodReports.size() ? "\n" : ",\n"));
            }
            out.write("  ]\n}\n");
        }
    }

    private static void field(BufferedWriter out, String name, String value,
                              boolean last, int indent) throws java.io.IOException {
        for (int i = 0; i < indent; i++) out.write("  ");
        out.write(quote(name));
        out.write(": ");
        out.write(value);
        out.write(last ? "\n" : ",\n");
    }

    private static String quote(String value) {
        if (value == null) return "null";
        StringBuilder result = new StringBuilder(value.length() + 16).append('"');
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"': result.append("\\\""); break;
                case '\\': result.append("\\\\"); break;
                case '\n': result.append("\\n"); break;
                case '\r': result.append("\\r"); break;
                case '\t': result.append("\\t"); break;
                default:
                    if (c < 0x20) result.append(String.format("\\u%04x", (int) c));
                    else result.append(c);
            }
        }
        return result.append('"').toString();
    }
}
