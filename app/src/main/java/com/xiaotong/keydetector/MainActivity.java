package com.xiaotong.keydetector;

import static com.xiaotong.keydetector.Util.getCheckerContext;

import android.app.Activity;
import android.graphics.Color;
import android.os.Bundle;
import android.view.Gravity;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import com.xiaotong.keydetector.checker.Checker;

import java.util.Map;

public class MainActivity extends Activity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(32, 32, 32, 32);
        root.setGravity(Gravity.CENTER_HORIZONTAL);

        TextView title = new TextView(this);
        title.setText("Key Detector");
        title.setTextSize(20);
        title.setGravity(Gravity.CENTER);
        title.setPadding(0, 0, 0, 32);
        root.addView(title);

        Button btn = new Button(this);
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

        scrollView.setBackgroundColor(Color.parseColor("#F0F0F0"));
        scrollView.setPadding(16,16,16,16);

        TextView tvResult = new TextView(this);
        tvResult.setText("点击按钮开始检测...");
        tvResult.setTextSize(14);
        tvResult.setTypeface(android.graphics.Typeface.MONOSPACE);
        tvResult.setTextColor(Color.BLACK);

        scrollView.addView(tvResult);
        root.addView(scrollView);

        setContentView(root);

        btn.setOnClickListener(v -> {
            btn.setEnabled(false);
            tvResult.setText("正在生成密钥并验证证书链...\n请稍候...");
            tvResult.setTextColor(Color.DKGRAY);

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
                    int color = Color.parseColor("#006400");
                    if ((finalCode & 1) != 0) tvResult.setTextColor(Color.RED);
                    tvResult.setTextColor(color);
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
