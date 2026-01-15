package com.xiaotong.keydetector.checker;

import static com.xiaotong.keydetector.Constant.KEYSTORE_PROVIDER;

import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Log;
import com.xiaotong.keydetector.AttestationExtension;
import com.xiaotong.keydetector.CheckerContext;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;

/**
 * 密钥认证安全级别检测器
 *
 * 检测原理：
 * - 检查密钥认证的安全级别
 * - 区分软件级别、可信执行环境 (TEE) 级别和 StrongBox 级别
 * - 软件级别的认证可以通过 hook 伪造
 *
 * 安全级别：
 * - 0（软件）：软件级别，可以通过 hook 伪造
 * - 1（TEE）：可信执行环境，硬件隔离
 * - 2（StrongBox）：独立安全芯片，最高安全级别
 *
 * 检测方法：
 * 1. 生成密钥对并获取认证
 * 2. 解析 attestationSecurityLevel 字段
 * 3. 如果是软件级别，则可能表明存在 hook
 *
 * 检测目标：
 * - TrickyStore 和其他 hook 框架
 * - 伪造的认证（软件级别）
 * - 不支持硬件认证的设备
 */
public final class AttestationSecurityLevelChecker extends Checker {
    private static final String TEST_ALIAS = "KeyDetector_SecLevel_Check";
    private static final String TAG = "AttestSecurityLevelChk";

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
                builder.setAttestationChallenge("KeyDetector_SecLevel_Challenge".getBytes());
            }

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                try {
                    builder.setIsStrongBoxBacked(true);
                    kpg.initialize(builder.build());
                    kpg.generateKeyPair();
                    Log.d(TAG, "Successfully generated StrongBox-backed key");
                } catch (Exception e) {
                    Log.d(TAG, "StrongBox not available, falling back to TEE");
                    builder.setIsStrongBoxBacked(false);
                    kpg.initialize(builder.build());
                    kpg.generateKeyPair();
                }
            } else {
                kpg.initialize(builder.build());
                kpg.generateKeyPair();
            }

            Certificate[] chain = keyStore.getCertificateChain(TEST_ALIAS);
            if (chain == null || chain.length == 0) {
                Log.w(TAG, "No certificate chain available");
                return false;
            }

            X509Certificate cert = (X509Certificate) chain[0];
            AttestationExtension ext = AttestationExtension.parse(cert);

            if (ext == null) {
                Log.w(TAG, "No attestation extension found - device may not support Key Attestation");
                return false;
            }

            Integer securityLevel = ext.getAttestationSecurityLevel();
            if (securityLevel == null) {
                Log.w(TAG, "Could not parse attestationSecurityLevel from attestation");
                return false;
            }

            String levelStr = AttestationExtension.securityLevelToString(securityLevel);
            Log.d(TAG, "Attestation Security Level: " + levelStr);

            if (securityLevel == AttestationExtension.KM_SECURITY_LEVEL_SOFTWARE) {
                Log.e(
                        TAG,
                        "ANOMALY: Attestation Security Level = SOFTWARE - "
                                + "Attestation is not hardware-backed and can be forged by Hook frameworks");
                return true;
            }

            if (securityLevel == AttestationExtension.KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT) {
                Log.d(TAG, "Attestation Security Level = TEE - Hardware-backed attestation");
                return false;
            }

            if (securityLevel == AttestationExtension.KM_SECURITY_LEVEL_STRONG_BOX) {
                Log.d(TAG, "Attestation Security Level = StrongBox - Highest security level");
                return false;
            }

            Log.w(TAG, "Unknown Attestation Security Level: " + securityLevel);
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

    @Override
    public String description() {
        return "Attestation Security Level Detection (%d) - attestation 为软件级别";
    }
}
