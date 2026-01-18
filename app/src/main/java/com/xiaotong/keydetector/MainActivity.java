package com.xiaotong.keydetector;

import static com.xiaotong.keydetector.Util.getCheckerContext;

import android.app.Activity;
import android.graphics.Color;
import android.graphics.Typeface;
import android.os.Bundle;
import android.view.Gravity;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowCompat;
import androidx.core.view.WindowInsetsCompat;
import com.google.android.material.button.MaterialButton;
import com.google.android.material.color.DynamicColors;
import com.google.android.material.color.MaterialColors;
import com.google.android.material.textview.MaterialTextView;
import com.xiaotong.keydetector.checker.Checker;
import java.util.Map;

public class MainActivity extends Activity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        DynamicColors.applyToActivityIfAvailable(this);
        WindowCompat.setDecorFitsSystemWindows(getWindow(), false);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setGravity(Gravity.CENTER_HORIZONTAL);

        root.setBackgroundColor(
                MaterialColors.getColor(this, com.google.android.material.R.attr.colorSurface, Color.WHITE));

        ViewCompat.setOnApplyWindowInsetsListener(root, (v, insets) -> {
            var systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars());
            v.setPadding(systemBars.left + 32, systemBars.top + 32, systemBars.right + 32, systemBars.bottom + 32);
            return WindowInsetsCompat.CONSUMED;
        });

        MaterialTextView title = new MaterialTextView(this);
        title.setText("Key Detector");
        title.setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_HeadlineSmall);
        title.setTextColor(
                MaterialColors.getColor(this, com.google.android.material.R.attr.colorOnSurface, Color.BLACK));
        title.setGravity(Gravity.CENTER);
        title.setLayoutParams(new LinearLayout.LayoutParams(-1, -2));
        title.setPadding(0, 32, 0, 48);
        root.addView(title);

        MaterialButton btn = new MaterialButton(this);
        btn.setText("开始检测 (Key Attestation)");
        root.addView(btn);

        ScrollView scrollView = new ScrollView(this);
        LinearLayout.LayoutParams scrollParams = new LinearLayout.LayoutParams(-1, -1);
        scrollParams.topMargin = 32;
        scrollView.setLayoutParams(scrollParams);

        int surfaceVariant = MaterialColors.getColor(
                this, com.google.android.material.R.attr.colorSurfaceContainerLow, Color.LTGRAY);
        scrollView.setBackgroundColor(surfaceVariant);
        scrollView.setPadding(16, 16, 16, 16);

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
            // 优化：使用语义化颜色属性
            tvResult.setTextColor(MaterialColors.getColor(
                    this, com.google.android.material.R.attr.colorOnSurfaceVariant, Color.GRAY));

            new Thread(() -> {
                        DetectorEngine detector = new DetectorEngine();
                        CheckerContext ctx = getCheckerContext(this);
                        int code = (ctx == null) ? 2 : detector.run(ctx);
                        String resultText = parseResult(code);

                        runOnUiThread(() -> {
                            tvResult.setText(resultText);
                            int targetAttr = (code == 1) ? android.R.attr.colorPrimary : android.R.attr.colorError;
                            tvResult.setTextColor(MaterialColors.getColor(this, targetAttr, Color.RED));
                            btn.setEnabled(true);
                        });
                    })
                    .start();
        });
    }

    private String parseResult(int code) {
        StringBuilder sb = new StringBuilder("Status Code: " + code + "\n状态码: " + code + "\n\n");
        if (code < 3) {
            sb.append(parseSimpleStatus(code));
            return sb.toString();
        }
        for (Map.Entry<Integer, Checker> entry : DetectorEngine.FlagCheckerMap.entrySet()) {
            if (entry.getValue() != null && (code & entry.getKey()) != 0) {
                sb.append(String.format(entry.getValue().description(), entry.getKey()))
                        .append("\n\n");
            }
        }
        return sb.toString();
    }

    private String parseSimpleStatus(int code) {
        return switch (code) {
            case 1 -> "Normal (1)";
            case 2 -> "Tampered Attestation Key (2)\n密钥生成 / 使用异常或证书链一致性异常";
            default -> "Something Wrong (" + code + ")";
        };
    }
}
