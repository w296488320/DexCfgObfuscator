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
            field(out, "schemaVersion", "3", false, 1);
            field(out, "variant", quote(variant), false, 1);
            field(out, "seed", quote(Long.toUnsignedString(config.seed)), false, 1);
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
            field(out, "switchesPadded", Integer.toString(stats.switchesPadded), false, 2);
            field(out, "switchCasesBefore", Integer.toString(stats.switchCasesBefore), false, 2);
            field(out, "switchCasesAfter", Integer.toString(stats.switchCasesAfter), false, 2);
            field(out, "fakeSwitchCases", Integer.toString(stats.fakeSwitchCases), false, 2);
            field(out, "symbolSwitchCases", Integer.toString(stats.symbolSwitchCases), false, 2);
            field(out, "regionalDispatchers", Integer.toString(stats.regionalDispatchers), false, 2);
            field(out, "reachableAliasCases", Integer.toString(stats.reachableAliasCases), false, 2);
            field(out, "stateSharedMethods", Integer.toString(stats.stateSharedMethods), false, 2);
            field(out, "obfuscatedRatio", Double.toString(stats.obfuscatedRatio()), false, 2);
            field(out, "originalDexBytes", Long.toString(stats.originalDexBytes), false, 2);
            field(out, "outputDexBytes", Long.toString(stats.outputDexBytes), false, 2);
            field(out, "sizeIncreasePercent", Double.toString(stats.sizeIncreasePercent()), true, 2);
            out.write("  },\n");
            out.write("  \"skipReasons\": {\n");
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
            field(out, "minObfuscatedRatio", Double.toString(config.minObfuscatedRatio), false, 2);
            field(out, "maxSizeIncreasePercent", Double.toString(config.maxSizeIncreasePercent), true, 2);
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
