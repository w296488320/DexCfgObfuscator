package com.hunter.dexcfgobf;

/** 单个方法的一次、唯一最终决策。用于统计和 JSON 报告，避免回退路径重复计数。 */
final class TransformationOutcome {
    enum Mode { FLATTENED, REORDERED, SKIPPED }

    enum Reason {
        FLATTEN_SAFE,
        VERIFIER_SEPARATED,
        TRY_CATCH_REORDER,
        VERIFIER_RISK_REORDER,
        FLATTEN_FALLBACK_REORDER,
        ALREADY_OBFUSCATED,
        TRY_CATCH_DISABLED,
        TOO_SMALL,
        TOO_LARGE,
        SWITCH_UNSUPPORTED,
        REGISTER_BUDGET,
        VERIFIER_ANALYSIS_FAILED,
        UNSUPPORTED
    }

    final Mode mode;
    final Reason reason;
    final String template;
    final boolean registerTypesSeparated;
    final int addedRegisters;
    final int switchesPadded;
    final int switchCasesBefore;
    final int switchCasesAfter;
    final int fakeSwitchCases;
    final int symbolSwitchCases;
    final int dispatcherRegions;
    final int reachableAliasCases;
    final int stateShareRegisters;

    TransformationOutcome(Mode mode, Reason reason, String template,
                          boolean registerTypesSeparated, int addedRegisters) {
        this(mode, reason, template, registerTypesSeparated, addedRegisters,
                0, 0, 0, 0, 0, 0, 0, 0);
    }

    TransformationOutcome(Mode mode, Reason reason, String template,
                          boolean registerTypesSeparated, int addedRegisters,
                          int switchesPadded, int switchCasesBefore, int switchCasesAfter,
                          int fakeSwitchCases, int symbolSwitchCases) {
        this(mode, reason, template, registerTypesSeparated, addedRegisters,
                switchesPadded, switchCasesBefore, switchCasesAfter, fakeSwitchCases,
                symbolSwitchCases, 0, 0, 0);
    }

    TransformationOutcome(Mode mode, Reason reason, String template,
                          boolean registerTypesSeparated, int addedRegisters,
                          int switchesPadded, int switchCasesBefore, int switchCasesAfter,
                          int fakeSwitchCases, int symbolSwitchCases,
                          int dispatcherRegions, int reachableAliasCases,
                          int stateShareRegisters) {
        this.mode = mode;
        this.reason = reason;
        this.template = template == null ? "none" : template;
        this.registerTypesSeparated = registerTypesSeparated;
        this.addedRegisters = addedRegisters;
        this.switchesPadded = switchesPadded;
        this.switchCasesBefore = switchCasesBefore;
        this.switchCasesAfter = switchCasesAfter;
        this.fakeSwitchCases = fakeSwitchCases;
        this.symbolSwitchCases = symbolSwitchCases;
        this.dispatcherRegions = dispatcherRegions;
        this.reachableAliasCases = reachableAliasCases;
        this.stateShareRegisters = stateShareRegisters;
    }

    static TransformationOutcome skipped(Reason reason) {
        return new TransformationOutcome(Mode.SKIPPED, reason, "none", false, 0);
    }
}
