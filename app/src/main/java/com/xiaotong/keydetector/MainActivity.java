package com.xiaotong.keydetector;

import static com.xiaotong.keydetector.Util.getCheckerContext;

import android.app.Activity;
import android.graphics.Color;
import android.graphics.Typeface;
import android.os.Bundle;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowCompat;
import androidx.core.view.WindowInsetsCompat;
import com.google.android.material.button.MaterialButton;
import com.google.android.material.color.DynamicColors;
import com.google.android.material.textview.MaterialTextView;
import com.google.android.material.color.MaterialColors;
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

        TypedValue typedValue = new TypedValue();
        getTheme().resolveAttribute(com.google.android.material.R.attr.colorSurfaceContainerLow, typedValue, true);
        scrollView.setBackgroundColor(typedValue.data);
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

            int neutralColor = MaterialColors.getColor(this, com.google.android.material.R.attr.colorOnSurfaceVariant, Color.GRAY);
            tvResult.setTextColor(neutralColor);

            new Thread(() -> {
                DetectorEngine detector = new DetectorEngine();
                int code;
                CheckerContext ctx = getCheckerContext(this);
                if (ctx == null) {
                    code = 2;
                } else {
                    code = detector.run(ctx);
                }
                String resultText = parseResult(code);

                final int finalCode = code;
                runOnUiThread(() -> {
                    tvResult.setText(resultText);

                    if ((finalCode & 1) == 0) {
                        int successColor = MaterialColors.getColor(this, com.google.android.material.R.attr.colorPrimary, Color.BLUE);
                        tvResult.setTextColor(successColor);
                    } else {
                        int errorColor = MaterialColors.getColor(this, com.google.android.material.R.attr.colorError, Color.RED);
                        tvResult.setTextColor(errorColor);
                    }
                    btn.setEnabled(true);
                });
            }).start();
        });
    }

    private String parseResult(int code) {
        StringBuilder sb = new StringBuilder();
        sb.append("Status Code: ").append(code).append("\n")
                .append("状态码: ").append(code).append("\n\n");
        if (code < 3) {
            sb.append(parseSimpleStatus(code));
            return sb.toString();
        }
        for (Map.Entry<Integer, Checker> entry : DetectorEngine.FlagCheckerMap.entrySet()) {
            int flag = entry.getKey();
            Checker checker = entry.getValue();
            if (checker != null && (code & flag) != 0) {
                sb.append(String.format(checker.description(), flag))
                        .append("\n\n");
            }
        }
        return sb.toString();
    }

    private String parseSimpleStatus(int code) {
        switch (code) {
            case 1:
                return "Normal (1)";
            case 2:
                return "Tampered Attestation Key (2)\n"
                        + "密钥生成 / 使用异常或证书链一致性异常";
            default:
                return String.format("Something Wrong (%s)", code);
        }
    }
}
