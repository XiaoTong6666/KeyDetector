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
 * Bootloader 解锁检测器
 *
 * 检测原理：
 * - 通过 Android 密钥认证获取硬件级设备状态
 * - 从证书扩展中提取 RootOfTrust 信息
 * - 检查 deviceLocked 字段以确定 Bootloader 是否已解锁
 *
 * 检测方法：
 * 1. 生成基于认证的密钥对
 * 2. 获取证书链
 * 3. 从认证扩展中解析 RootOfTrust
 * 4. 检查 deviceLocked 字段
 *
 * 检测目标：
 * - Bootloader 解锁状态
 * - 无法通过软件级钩子伪造（由 TEE/StrongBox 签名）
 *
 * 注意：
 * - 需要 Android 7.0+ (API 24)
 * - 设备必须支持密钥认证
 */
public final class BootloaderUnlockedChecker extends Checker {
    private static final String TEST_ALIAS = "KeyDetector_BL_Check";
    private static final String TAG = "BootloaderUnlockedChk";

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
                builder.setAttestationChallenge("KeyDetector_BL_Challenge".getBytes());
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

            Boolean deviceLocked = rot.getDeviceLocked();
            if (deviceLocked == null) {
                Log.w(TAG, "Could not parse deviceLocked status from attestation");
                return false;
            }

            if (!deviceLocked) {
                Log.e(TAG, "ANOMALY: Bootloader is UNLOCKED - deviceLocked=false in attestation");
                Log.d(TAG, "RootOfTrust source: " + (rot.isFromTeeEnforced() ? "TEE" : "Software"));
                return true;
            }

            Log.d(TAG, "Bootloader is locked - deviceLocked=true");
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
        return "Bootloader Unlocked Detection (%d) - Bootloader 为解锁状态";
    }
}
