package com.example.dexcfgsample;

import android.app.Activity;
import android.os.Bundle;
import android.widget.TextView;

public final class MainActivity extends Activity {
    private static final String RETRACE_CRASH_EXTRA =
            "com.example.dexcfgsample.CRASH_FOR_RETRACE";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        if (getIntent().getBooleanExtra(RETRACE_CRASH_EXTRA, false)) {
            ReleaseCrashProbe.divideForRetrace(0);
        }
        TextView content = new TextView(this);
        content.setText(SamplePayload.messageFor(7));
        content.setTextSize(18.0f);
        int padding = (int) (24 * getResources().getDisplayMetrics().density);
        content.setPadding(padding, padding, padding, padding);
        setContentView(content);
    }
}
