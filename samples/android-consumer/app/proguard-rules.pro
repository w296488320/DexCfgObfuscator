# Keep the neutral fixture present for post-R8 inspection while still allowing R8 to optimize and
# rename it. This exercises the plugin's source-name-to-final-DEX mapping path.
-keep,allowoptimization,allowobfuscation class com.example.dexcfgsample.SamplePayload { *; }
