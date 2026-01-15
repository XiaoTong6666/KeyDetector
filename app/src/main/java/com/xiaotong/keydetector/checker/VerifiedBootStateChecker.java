package com.xiaotong.keydetector.checker;

import static com.xiaotong.keydetector.Constant.KEYSTORE_PROVIDER;

import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Log;
import com.xiaotong.keydetector.CheckerContext;
import com.xiaotong.keydetector.RootOfTrust;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;

/**
 * 已验证启动状态检查器
 *
 * 检测原理：
 * - 通过 Android 密钥认证获取已验证启动状态
 * - 从 RootOfTrust 中提取 verifiedBootState 字段
 * - 检测系统完整性和篡改情况
 *
 * 已验证启动状态：
 * - 0（已验证）：官方系统，完全验证
 * - 1（自签名）：自签名系统（自定义 ROM）
 * - 2（未验证）：未验证（系统已修改）
 * - 3（失败）：验证失败
 *
 * 检测方法：
 * 1. 生成基于认证的密钥对
 * 2. 从证书链中解析认证扩展
 * 3. 从 RootOfTrust 中提取 verifiedBootState
 * 4. 判断系统是否可信
 *
 * 检测目标：
 * - 系统完整性
 * - 是否运行自定义 ROM
 * - 系统是否被篡改
 */
public final class VerifiedBootStateChecker extends Checker {
    private static final String TEST_ALIAS = "KeyDetector_VB_Check";
    private static final String TAG = "VerifiedBootStateChk";

    private static final int KM_VERIFIED_BOOT_VERIFIED = 0;
    private static final int KM_VERIFIED_BOOT_SELF_SIGNED = 1;
    private static final int KM_VERIFIED_BOOT_UNVERIFIED = 2;
    private static final int KM_VERIFIED_BOOT_FAILED = 3;

    @Override
    public String name() {
        return this.getClass().getName();
    }

    @Override
    public boolean check(CheckerContext ctx) throws Exception {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.N) {
            Log.w(TAG, "Key Attestation requires Android 7.0+");
            return false;
        }

        KeyStore keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER);
        keyStore.load(null);

        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, KEYSTORE_PROVIDER);

            KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(
                            TEST_ALIAS, KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                    .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512);

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                builder.setAttestationChallenge("KeyDetector_VB_Challenge".getBytes());
            }

            kpg.initialize(builder.build());
            kpg.generateKeyPair();

            Certificate[] chain = keyStore.getCertificateChain(TEST_ALIAS);
            if (chain == null || chain.length == 0) {
                Log.w(TAG, "No certificate chain available");
                return false;
            }

            X509Certificate cert = (X509Certificate) chain[0];
            RootOfTrust rot = RootOfTrust.parse(cert);

            if (rot == null) {
                Log.w(TAG, "No attestation extension found - device may not support Key Attestation");
                return false;
            }

            Integer bootState = rot.getVerifiedBootState();
            if (bootState == null) {
                Log.w(TAG, "Could not parse verifiedBootState from attestation");
                return false;
            }

            String bootStateStr = verifiedBootStateToString(bootState);
            Log.d(TAG, "Verified Boot State: " + bootStateStr);
            Log.d(TAG, "RootOfTrust source: " + (rot.isFromTeeEnforced() ? "TEE" : "Software"));

            if (bootState == KM_VERIFIED_BOOT_SELF_SIGNED) {
                Log.e(TAG, "ANOMALY: Verified Boot State = SELF_SIGNED - Running custom ROM or modified system");
                return true;
            }

            if (bootState == KM_VERIFIED_BOOT_UNVERIFIED) {
                Log.e(TAG, "ANOMALY: Verified Boot State = UNVERIFIED - System integrity compromised");
                return true;
            }

            if (bootState == KM_VERIFIED_BOOT_FAILED) {
                Log.e(TAG, "ANOMALY: Verified Boot State = FAILED - Boot verification failed");
                return true;
            }

            if (bootState == KM_VERIFIED_BOOT_VERIFIED) {
                Log.d(TAG, "Verified Boot State = VERIFIED - System is trusted");
                return false;
            }

            Log.w(TAG, "Unknown Verified Boot State: " + bootState);
            return false;

        } catch (Exception e) {
            Log.w(TAG, "Check failed: " + e.getMessage(), e);
            return false;
        } finally {
            try {
                if (keyStore.containsAlias(TEST_ALIAS)) {
                    keyStore.deleteEntry(TEST_ALIAS);
                }
            } catch (Exception ignored) {
            }
        }
    }

    private String verifiedBootStateToString(int state) {
        switch (state) {
            case KM_VERIFIED_BOOT_VERIFIED:
                return "Verified";
            case KM_VERIFIED_BOOT_SELF_SIGNED:
                return "Self-signed";
            case KM_VERIFIED_BOOT_UNVERIFIED:
                return "Unverified";
            case KM_VERIFIED_BOOT_FAILED:
                return "Failed";
            default:
                return "Unknown (" + state + ")";
        }
    }

    @Override
    public String description() {
        return "Verified Boot State Detection (%d) - 系统不完整 或 启动验证状态存在异常";
    }
}
