package com.example.dexcfgsample;

/** Neutral fixture with both string constants and branch-heavy bytecode for release inspection. */
public final class SamplePayload {
    public static final String DEMO_ENDPOINT = "https://api.example.invalid/v1/demo";

    private SamplePayload() {
    }

    public static String messageFor(int accountState) {
        String state;
        if (accountState < 0) {
            state = "sample state: invalid";
        } else if ((accountState & 1) == 0) {
            state = "sample state: even";
        } else {
            state = "sample state: odd";
        }

        int checksum = 17;
        for (int i = 0; i < 4; i++) {
            checksum = checksum * 31 + accountState + i;
        }
        return "DexCfgObfuscator consumer is running\n"
                + state
                + "\nendpoint=" + DEMO_ENDPOINT
                + "\nchecksum=" + checksum;
    }
}
