# Keep the neutral fixture present for post-R8 inspection while still allowing R8 to optimize and
# rename it. This exercises the plugin's source-name-to-final-DEX mapping path.
-keep,allowoptimization,allowobfuscation class com.example.dexcfgsample.SamplePayload { *; }

# Keep the real-device crash probe as a distinct R8 frame and prevent constant folding/inlining,
# while still renaming it so the retrace check proves class/method and residual-line restoration.
-keep,allowobfuscation class com.example.dexcfgsample.ReleaseCrashProbe {
    public static int divideForRetrace(int);
}
