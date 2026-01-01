package com.xiaotong.keydetector;

import android.app.Activity;
import android.graphics.Typeface;
import android.os.Bundle;
import android.view.Gravity;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.ScrollView;

import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowCompat;
import androidx.core.view.WindowInsetsCompat;

import com.google.android.material.button.MaterialButton;
import com.google.android.material.textview.MaterialTextView;
import com.google.android.material.color.DynamicColors;

public class MainActivity extends Activity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        DynamicColors.applyToActivityIfAvailable(this);
        WindowCompat.setDecorFitsSystemWindows(getWindow(), false);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setGravity(Gravity.CENTER_HORIZONTAL);

        ViewCompat.setOnApplyWindowInsetsListener(root, (v, insets) -> {
            Insets systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars());
            v.setPadding(systemBars.left + 32, systemBars.top + 32, systemBars.right + 32, systemBars.bottom + 32);
            return WindowInsetsCompat.CONSUMED;
        });

        MaterialTextView title = new MaterialTextView(this);
        title.setText("Key Detector");
        title.setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_HeadlineSmall);
        title.setGravity(Gravity.CENTER);
        title.setPadding(0, 0, 0, 32);
        root.addView(title);

        MaterialButton btn = new MaterialButton(this);
        btn.setId(ViewGroup.generateViewId());
        btn.setText("开始检测 (Key Attestation)");
        root.addView(btn);

        ScrollView scrollView = new ScrollView(this);
        LinearLayout.LayoutParams scrollParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT
        );
        scrollParams.topMargin = 32;
        scrollView.setLayoutParams(scrollParams);

        MaterialTextView tvResult = new MaterialTextView(this);
        tvResult.setText("点击按钮开始检测...");
        tvResult.setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_BodyMedium);
        tvResult.setTypeface(Typeface.MONOSPACE);

        scrollView.addView(tvResult);
        root.addView(scrollView);

        setContentView(root);

        btn.setOnClickListener(v -> {
            btn.setEnabled(false);
            tvResult.setText("正在生成密钥并验证证书链...\n请稍候...");

            new Thread(() -> {
                PoCDetector detector = new PoCDetector(getApplicationContext());
                int code = detector.runDetection();

                String resultText = parseResult(code);

                runOnUiThread(() -> {
                    tvResult.setText(resultText);
                    boolean ok = (code & 1) != 0
                            && (code & (2 | 8 | 16 | 32 | 64 | 128 | 256 | 512)) == 0;
                    if (!ok) {
                        tvResult.setTextColor(getColor(com.google.android.material.R.color.material_dynamic_primary0));
                    } else {
                        tvResult.setTextColor(getColor(com.google.android.material.R.color.material_dynamic_tertiary70));
                    }
                    btn.setEnabled(true);
                });
            }).start();
        });
    }

    private String parseResult(int code) {
        StringBuilder sb = new StringBuilder();
        sb.append("状态码: ").append(code).append("\n");

        if ((code & 1) != 0) {
            sb.append("Normal (1)\n");
        } else {
            sb.append("Abnormal (missing 1)\n");
        }

        if ((code & 2) != 0) {
            sb.append("Tampered Attestation Key (2)\n");
            sb.append("密钥生成/使用异常或证书链一致性异常\n");
        }
        if ((code & 4) != 0) {
            sb.append("Hook Failed (4)\n");
            sb.append("尝试 Hook ServiceManager 失败\n");
        }
        if ((code & 8) != 0) {
            sb.append("AOSP Attestation Key (8)\n");
            sb.append("检测到软件级 (AOSP) 根证书\n");
        }
        if ((code & 16) != 0) {
            sb.append("Unknown Attestation Key (16)\n");
            sb.append("根证书未知\n");
        }
        if ((code & 32) != 0) {
            sb.append("VBMeta Mismatch (32)\n");
            sb.append("VBMeta Hash 不一致或 Attestation Challenge 不匹配（可能重放）\n");
        }
        if ((code & 64) != 0) {
            sb.append("Broken Chain (64)\n");
            sb.append("证书链签名验证失败，疑似中间人篡改\n");
        }
        if ((code & 128) != 0) {
            sb.append("Key Mismatch (128)\n");
            sb.append("私钥与证书公钥不匹配，严重的欺诈行为\n");
        }
        if ((code & 256) != 0) {
            sb.append("Revoked Key (256)\n");
            sb.append("检测到已泄露的黑名单密钥\n");
        }
        if ((code & 512) != 0) {
            sb.append("Patch Mode Detected (512)\n");
            sb.append("生成路径与读取路径返回的证书不一致，疑似被 Patch / Hack / 重签名\n");
        }

        return sb.toString();
    }
}
