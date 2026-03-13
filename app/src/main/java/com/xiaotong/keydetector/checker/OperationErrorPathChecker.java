package com.xiaotong.keydetector.checker;

import static com.xiaotong.keydetector.Constant.KEYSTORE_PROVIDER;

import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Log;
import com.xiaotong.keydetector.CheckerContext;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.spec.ECGenParameterSpec;

/**
 * Keystore 2.0 IKeystoreOperation 错误路径语义检测
 *
 * 检测原理：
 * - AOSP Keystore2 对 IKeystoreOperation 的 updateAad/update/abort 等接口有固定错误语义
 * - 调用失败时，正常路径应通过 ServiceSpecificException 返回 Keystore2/KeyMint 错误码
 * - 例如：
 *   1. 输入超过 0x8000 字节，应返回 TOO_MUCH_DATA
 *   2. abort() 之后再次调用 update()，应返回 INVALID_OPERATION_HANDLE
 * - 某些 Hook/模拟实现没有完整复刻这些状态机与异常映射，容易暴露异常
 *
 * 检测方法：
 * 1. 生成一个测试签名密钥
 * 2. 使用最小 AOSP 风格参数通过 IKeystoreSecurityLevel.createOperation() 创建签名操作
 * 3. 若 createOperation() 对有效签名 key 异常失败，则直接记为异常
 * 4. 必要时使用带 ALGORITHM 的兼容参数继续创建操作，避免后续探针被提前短路
 * 5. 探测 updateAad 的异常路径是否走 ServiceSpecificException
 * 6. 探测超长输入 update() 是否按 AOSP 返回错误
 * 7. 探测 abort() 之后操作句柄是否失效
 *
 * 判定规则：
 * - 若 createOperation() 对有效签名 key 异常失败，视为异常
 * - 若错误没有走 ServiceSpecificException 通道，视为异常
 * - 若超长输入被直接接受，视为异常
 * - 若 abort() 后句柄仍可继续使用，或错误码不是 INVALID_OPERATION_HANDLE，视为异常
 *
 * 检测目标：
 * - TEESimulator 软件 operation 对状态机和异常映射实现不完整的问题
 * - 其他仿真 IKeystoreOperation 但没有严格对齐 AOSP 错误语义的 Hook 实现
 */
public final class OperationErrorPathChecker extends Checker {
    private static final String TAG = "OperationErrorChecker";
    private static final String TEST_ALIAS = "KeyDetector_OpErr";
    private static final int LARGE_INPUT_SIZE = 0x8001;

    @Override
    public String name() {
        return this.getClass().getName();
    }

    @Override
    public boolean check(CheckerContext ctx) throws Exception {
        if (Build.VERSION.SDK_INT < 31) {
            return false;
        }

        KeyStore keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER);
        keyStore.load(null);

        try {
            cleanupAlias(keyStore);
            generateSigningKey();

            ProbeContext probeContext = createProbeContext();
            if (probeContext == null) {
                return false;
            }

            BootstrapResult bootstrapResult = bootstrapOperationParameters(probeContext);
            boolean anomalyDetected = bootstrapResult.anomalyDetected;
            if (bootstrapResult.operationParameters == null) {
                return true;
            }
            probeContext.activeSigningParameters = bootstrapResult.operationParameters;

            if (probeUpdateAad(probeContext)) {
                return true;
            }
            if (probeTooMuchData(probeContext)) {
                return true;
            }
            if (probeInvalidHandleAfterAbort(probeContext)) {
                return true;
            }

            if (anomalyDetected) {
                Log.e(
                        TAG,
                        "ANOMALY: createOperation required compatibility parameters before later probes could run.");
                return true;
            }

            Log.d(TAG, "Check passed: operation error path matches native Keystore2 semantics.");
            return false;
        } catch (Throwable t) {
            Log.w(TAG, "Check failed", t);
            return false;
        } finally {
            cleanupAlias(keyStore);
        }
    }

    private void generateSigningKey() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, KEYSTORE_PROVIDER);
        kpg.initialize(new KeyGenParameterSpec.Builder(TEST_ALIAS, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .build());
        kpg.generateKeyPair();
    }

    private ProbeContext createProbeContext() throws Exception {
        Object service = Reflection.getIKeystoreService();
        Object keyEntryResponse = Reflection.getKeyEntry(service, Reflection.createKeyDescriptor(TEST_ALIAS));
        Object returnedKeyDescriptor = Reflection.getReturnedKeyDescriptor(keyEntryResponse);

        Object iSecurityLevel = Reflection.getSecurityLevelBinder(keyEntryResponse);
        if (iSecurityLevel == null) {
            iSecurityLevel = Reflection.getTrustedEnvironmentSecurityLevel(service);
        }

        if (iSecurityLevel == null) {
            Log.w(TAG, "Could not resolve IKeystoreSecurityLevel binder.");
            return null;
        }

        Object operationDescriptor = returnedKeyDescriptor;
        if (Reflection.getIntField(returnedKeyDescriptor, "domain") != Reflection.getDomainKeyId()) {
            long nspace = Reflection.getLongField(returnedKeyDescriptor, "nspace");
            operationDescriptor = Reflection.createKeyIdDescriptor(nspace, TEST_ALIAS);
            Log.w(
                    TAG,
                    "getKeyEntry did not return KEY_ID descriptor; reconstructing KEY_ID descriptor for follow-up probes.");
        }

        return new ProbeContext(
                operationDescriptor,
                iSecurityLevel,
                Reflection.createSigningOperationParameters(),
                Reflection.createSigningOperationParametersWithAlgorithm());
    }

    private BootstrapResult bootstrapOperationParameters(ProbeContext probeContext) throws Exception {
        Object operation = null;
        try {
            operation = createSigningOperation(probeContext, probeContext.minimalSigningParameters);
            Log.d(TAG, "createOperation accepted minimal AOSP-style params.");
            return new BootstrapResult(probeContext.minimalSigningParameters, false);
        } catch (Throwable t) {
            Log.e(
                    TAG,
                    "ANOMALY: createOperation failed for a valid signing key using minimal AOSP-style params: "
                            + Reflection.describeThrowable(t));
        } finally {
            abortQuietly(operation);
        }

        operation = null;
        try {
            operation = createSigningOperation(probeContext, probeContext.compatibilitySigningParameters);
            Log.w(
                    TAG,
                    "createOperation succeeded only after adding compatibility parameters; continuing with fallback params.");
            return new BootstrapResult(probeContext.compatibilitySigningParameters, true);
        } catch (Throwable t) {
            Log.e(
                    TAG,
                    "ANOMALY: createOperation also failed with compatibility parameters: "
                            + Reflection.describeThrowable(t));
            return new BootstrapResult(null, true);
        } finally {
            abortQuietly(operation);
        }
    }

    private boolean probeUpdateAad(ProbeContext probeContext) throws Exception {
        Object operation = createSigningOperation(probeContext);
        try {
            Method updateAadMethod = operation.getClass().getMethod("updateAad", byte[].class);
            updateAadMethod.invoke(operation, "aad".getBytes(StandardCharsets.UTF_8));
            Log.w(TAG, "updateAad unexpectedly succeeded on a signing operation; treat as inconclusive.");
            return false;
        } catch (Throwable t) {
            if (!Reflection.isServiceSpecificException(t)) {
                Log.e(
                        TAG,
                        "ANOMALY: updateAad failed outside ServiceSpecificException path: "
                                + Reflection.describeThrowable(t));
                return true;
            }

            Log.d(
                    TAG,
                    "updateAad returned ServiceSpecificException as expected. code="
                            + Reflection.getServiceSpecificErrorCode(t));
            return false;
        } finally {
            abortQuietly(operation);
        }
    }

    private boolean probeTooMuchData(ProbeContext probeContext) throws Exception {
        Object operation = createSigningOperation(probeContext);
        try {
            Method updateMethod = operation.getClass().getMethod("update", byte[].class);
            updateMethod.invoke(operation, new Object[] {new byte[LARGE_INPUT_SIZE]});
            Log.e(TAG, "ANOMALY: update accepted input larger than 0x8000 bytes.");
            return true;
        } catch (Throwable t) {
            if (!Reflection.isServiceSpecificException(t)) {
                Log.e(
                        TAG,
                        "ANOMALY: oversized update failed outside ServiceSpecificException path: "
                                + Reflection.describeThrowable(t));
                return true;
            }

            Log.d(
                    TAG,
                    "oversized update returned ServiceSpecificException as expected. code="
                            + Reflection.getServiceSpecificErrorCode(t)
                            + " expectedTooMuchData="
                            + Reflection.getTooMuchDataResponseCode());
            return false;
        } finally {
            abortQuietly(operation);
        }
    }

    private boolean probeInvalidHandleAfterAbort(ProbeContext probeContext) throws Exception {
        Object operation = createSigningOperation(probeContext);
        Method abortMethod = operation.getClass().getMethod("abort");
        abortMethod.invoke(operation);

        try {
            Method updateMethod = operation.getClass().getMethod("update", byte[].class);
            updateMethod.invoke(operation, "after_abort".getBytes(StandardCharsets.UTF_8));
            Log.e(TAG, "ANOMALY: operation remained usable after abort().");
            return true;
        } catch (Throwable t) {
            if (!Reflection.isServiceSpecificException(t)) {
                Log.e(
                        TAG,
                        "ANOMALY: post-abort update failed outside ServiceSpecificException path: "
                                + Reflection.describeThrowable(t));
                return true;
            }

            int errorCode = Reflection.getServiceSpecificErrorCode(t);
            int expected = Reflection.getInvalidOperationHandleError();
            if (errorCode != expected) {
                Log.e(
                        TAG,
                        "ANOMALY: post-abort update returned wrong error code. actual="
                                + errorCode
                                + " expected="
                                + expected);
                return true;
            }

            Log.d(TAG, "post-abort update returned INVALID_OPERATION_HANDLE as expected.");
            return false;
        }
    }

    private Object createSigningOperation(ProbeContext probeContext) throws Exception {
        return createSigningOperation(probeContext, probeContext.activeSigningParameters);
    }

    private Object createSigningOperation(ProbeContext probeContext, Object operationParameters) throws Exception {
        Object createOperationResponse = Reflection.createOperation(
                probeContext.securityLevelBinder, probeContext.keyIdDescriptor, operationParameters);
        Object operation = Reflection.getOperationBinder(createOperationResponse);
        if (operation == null) {
            throw new IllegalStateException("createOperation returned null iOperation");
        }
        return operation;
    }

    private void abortQuietly(Object operation) {
        if (operation == null) {
            return;
        }
        try {
            Method abortMethod = operation.getClass().getMethod("abort");
            abortMethod.invoke(operation);
        } catch (Throwable ignored) {
        }
    }

    private void cleanupAlias(KeyStore keyStore) {
        try {
            if (keyStore.containsAlias(TEST_ALIAS)) {
                keyStore.deleteEntry(TEST_ALIAS);
            }
        } catch (Exception ignored) {
        }
    }

    @Override
    public String description() {
        return "IKeystoreOperation Error-Path Anomaly (%d) - createOperation / ServiceSpecificException / TOO_MUCH_DATA / INVALID_OPERATION_HANDLE 语义异常";
    }

    private static final class ProbeContext {
        final Object keyIdDescriptor;
        final Object securityLevelBinder;
        final Object minimalSigningParameters;
        final Object compatibilitySigningParameters;
        Object activeSigningParameters;

        ProbeContext(
                Object keyIdDescriptor,
                Object securityLevelBinder,
                Object minimalSigningParameters,
                Object compatibilitySigningParameters) {
            this.keyIdDescriptor = keyIdDescriptor;
            this.securityLevelBinder = securityLevelBinder;
            this.minimalSigningParameters = minimalSigningParameters;
            this.compatibilitySigningParameters = compatibilitySigningParameters;
            this.activeSigningParameters = minimalSigningParameters;
        }
    }

    private static final class BootstrapResult {
        final Object operationParameters;
        final boolean anomalyDetected;

        BootstrapResult(Object operationParameters, boolean anomalyDetected) {
            this.operationParameters = operationParameters;
            this.anomalyDetected = anomalyDetected;
        }
    }
}
