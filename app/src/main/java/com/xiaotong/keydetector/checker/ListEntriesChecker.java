package com.xiaotong.keydetector.checker;

import static com.xiaotong.keydetector.Constant.KEYSTORE_PROVIDER;

import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Log;
import com.xiaotong.keydetector.CheckerContext;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

/**
 * Keystore 2.0 ListEntries Consistency Checker
 *
 * 检测原理：
 * - Hook 框架（如 TEESimulator）拦截 containsAlias()（内部调用 getKeyEntry）
 * - Hook 框架可能不拦截 aliases()（内部调用 listEntries）
 * - containsAlias() 返回 true（Hook 返回虚假密钥）
 * - aliases() 不包含该密钥（真实 Keystore2 数据库中没有）
 * - 这种不一致说明密钥只存在于 Hook 缓存中
 *
 * 检测方法：
 * 1. 生成测试密钥
 * 2. 调用 containsAlias() 检查密钥是否存在
 * 3. 调用 aliases() 获取所有密钥列表
 * 4. 检查两者是否一致
 *
 * 关键：必须使用 Java API 的 aliases()，而不是直接调用 Binder！
 * 因为 Hook 框架在 Java API 层拦截，直接调用 Binder 会绕过 Hook。
 *
 * 检测目标：
 * - TrickyStore
 * - TEESimulator
 * - 其他不完整的 Hook 实现
 */
public final class ListEntriesChecker extends Checker {
    private static final String TAG = "ListEntriesChecker";
    private static final String TEST_ALIAS = "KeyDetector_ListEntries";

    @Override
    public String name() {
        return this.getClass().getName();
    }

    @Override
    public boolean check(CheckerContext ctx) {
        if (Build.VERSION.SDK_INT < 31) {
            return false;
        }

        KeyStore keyStore = null;
        try {
            keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER);
            keyStore.load(null);
        } catch (Exception e) {
            Log.e(TAG, "Failed to initialize KeyStore", e);
            return false;
        }

        try {
            if (keyStore.containsAlias(TEST_ALIAS)) {
                keyStore.deleteEntry(TEST_ALIAS);
            }

            KeyPairGenerator kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, KEYSTORE_PROVIDER);
            kpg.initialize(new KeyGenParameterSpec.Builder(TEST_ALIAS, KeyProperties.PURPOSE_SIGN)
                    .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .build());
            kpg.generateKeyPair();

            boolean containsAliasResult = keyStore.containsAlias(TEST_ALIAS);

            Enumeration<String> aliasesEnum = keyStore.aliases();
            List<String> aliasesList = new ArrayList<>();
            while (aliasesEnum.hasMoreElements()) {
                aliasesList.add(aliasesEnum.nextElement());
            }
            boolean aliasesContainsKey = aliasesList.contains(TEST_ALIAS);

            if (containsAliasResult && !aliasesContainsKey) {
                Log.e(TAG, "ANOMALY: listEntries inconsistency detected! (contains=true, list=false)");
                Log.e(TAG, "ANOMALY: listEntries inconsistency detected!");
                Log.e(TAG, "• containsAlias() = true (getKeyEntry intercepted by Hook)");
                Log.e(TAG, "• aliases() doesn't contain key (listEntries not intercepted)");
                Log.e(TAG, "• Key exists only in Hook's cache, not in real Keystore2 DB");
                Log.e(TAG, "• Total aliases from real DB: " + aliasesList.size());
                return true;
            }

            if (!containsAliasResult && aliasesContainsKey) {
                Log.e(TAG, "ANOMALY: Reverse inconsistency detected! (contains=false, list=true)");
                Log.e(TAG, "• containsAlias() = false");
                Log.e(TAG, "• aliases() contains key = true");
                Log.e(TAG, "• This indicates abnormal getKeyEntry interception");
                return true;
                /*}

                if (containsAliasResult && aliasesContainsKey) {
                    Log.d(TAG, "Native Keystore2 behavior confirmed");
                    Log.d(TAG, "• containsAlias() = true");
                    Log.d(TAG, "• aliases() contains key = true");
                    Log.d(TAG, "• Key properly persisted to Keystore2 database");
                    return false;*/
            }

            Log.d(TAG, "Check passed: Consistent behavior between containsAlias and aliases.");
            return false;

        } catch (Exception e) {
            String stackTrace = Log.getStackTraceString(e);

            if (e instanceof android.os.BadParcelableException
                    || stackTrace.contains("BadParcelableException")
                    || stackTrace.contains("Parcelable too small")
                    || stackTrace.contains("KeyDescriptor.readFromParcel")) {

                Log.e(
                        TAG,
                        "CRITICAL: Hook Framework crashed during Binder transaction! This is a strong indicator for TEESimulator.",
                        e);
                return true;
            }

            Log.w(TAG, "Check failed with an unrelated exception.", e);
            return false;

        } finally {
            try {
                if (keyStore != null && keyStore.containsAlias(TEST_ALIAS)) {
                    keyStore.deleteEntry(TEST_ALIAS);
                }
            } catch (Exception cleanupException) {
                Log.w(TAG, "Failed to cleanup test key.", cleanupException);
            }
        }
    }

    @Override
    public String description() {
        return "IKeystoreService ListEntries Inconsistency (%d)\n检测 listEntries 是否被 Hook 且处理不当";
    }
}
