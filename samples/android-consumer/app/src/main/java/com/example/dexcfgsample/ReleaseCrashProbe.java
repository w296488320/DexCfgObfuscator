package com.example.dexcfgsample;

/** Explicit device-only crash path for validating stack retrace after strong CFG flattening. */
public final class ReleaseCrashProbe {
    private ReleaseCrashProbe() {
    }

    public static int divideForRetrace(int divisor) {
        int checksum = 17;
        for (int i = 0; i < 6; i++) {
            checksum = (checksum * 31) ^ (i * 7 + 3);
            if ((checksum & 1) == 0) {
                checksum += i;
            } else {
                checksum -= i;
            }
        }
        return checksum / divisor;
    }
}
