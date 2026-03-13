package com.xiaotong.keydetector.checker;

import android.os.IBinder;
import android.util.Log;
import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

public class Reflection {
    private static final String TAG = "Reflection";
    public static final int DOMAIN_APP = 0;
    public static final int DOMAIN_KEY_ID = 4;
    public static final long NSPACE_SELF = -1;
    public static final int SECURITY_LEVEL_TRUSTED_ENVIRONMENT = 1;
    public static final int KM_ERROR_INVALID_OPERATION_HANDLE = -28;
    public static final int RESPONSE_CODE_TOO_MUCH_DATA = 29;

    public static Object getIKeystoreService() throws Exception {
        Class<?> serviceManagerClass = Class.forName("android.os.ServiceManager");
        Method getServiceMethod = serviceManagerClass.getMethod("getService", String.class);
        IBinder binder = (IBinder) getServiceMethod.invoke(null, "android.system.keystore2.IKeystoreService/default");

        if (binder == null) {
            throw new Exception("Could not get IKeystoreService binder");
        }

        Class<?> stubClass = Class.forName("android.system.keystore2.IKeystoreService$Stub");
        Method asInterfaceMethod = stubClass.getMethod("asInterface", IBinder.class);
        return asInterfaceMethod.invoke(null, binder);
    }

    public static Object getTrustedEnvironmentSecurityLevel() throws Exception {
        return getTrustedEnvironmentSecurityLevel(getIKeystoreService());
    }

    public static Object getTrustedEnvironmentSecurityLevel(Object service) throws Exception {
        Method getSecurityLevelMethod = service.getClass().getMethod("getSecurityLevel", int.class);
        return getSecurityLevelMethod.invoke(service, getSecurityLevelTrustedEnvironment());
    }

    public static Object createKeyDescriptor(String alias) throws Exception {
        return createKeyDescriptor(getDomainApp(), NSPACE_SELF, alias);
    }

    public static Object createKeyIdDescriptor(long nspace, String alias) throws Exception {
        return createKeyDescriptor(getDomainKeyId(), nspace, alias);
    }

    public static Object createKeyDescriptor(int domain, long nspace, String alias) throws Exception {
        Class<?> keyDescriptorClass = Class.forName("android.system.keystore2.KeyDescriptor");
        Object keyDescriptor = keyDescriptorClass.getDeclaredConstructor().newInstance();

        Field domainField = keyDescriptorClass.getField("domain");
        domainField.setInt(keyDescriptor, domain);

        Field nspaceField = keyDescriptorClass.getField("nspace");
        nspaceField.setLong(keyDescriptor, nspace);

        Field aliasField = keyDescriptorClass.getField("alias");
        aliasField.set(keyDescriptor, alias);

        Field blobField = keyDescriptorClass.getField("blob");
        blobField.set(keyDescriptor, null);

        return keyDescriptor;
    }

    public static Object getKeyEntry(Object service, Object keyDescriptor) throws Exception {
        Method method = service.getClass().getMethod("getKeyEntry", keyDescriptor.getClass());
        return method.invoke(service, keyDescriptor);
    }

    public static Object listEntriesBatched(Object service, String startPastAlias) throws Exception {
        Method method = service.getClass().getMethod("listEntriesBatched", int.class, long.class, String.class);
        return method.invoke(service, getDomainApp(), NSPACE_SELF, startPastAlias);
    }

    public static Object createOperation(Object iSecurityLevel, Object keyDescriptor, Object keyParameters)
            throws Exception {
        Method method = iSecurityLevel
                .getClass()
                .getMethod("createOperation", keyDescriptor.getClass(), keyParameters.getClass(), boolean.class);
        return method.invoke(iSecurityLevel, keyDescriptor, keyParameters, false);
    }

    public static Object createSigningOperationParameters() throws Exception {
        Object purpose = createKeyParameter(getTag("PURPOSE"), "keyPurpose", int.class, getKeyPurpose("SIGN"));
        Object digest = createKeyParameter(getTag("DIGEST"), "digest", int.class, getDigest("SHA_2_256"));
        return newKeyParameterArray(purpose, digest);
    }

    public static Object createSigningOperationParametersWithAlgorithm() throws Exception {
        Object purpose = createKeyParameter(getTag("PURPOSE"), "keyPurpose", int.class, getKeyPurpose("SIGN"));
        Object digest = createKeyParameter(getTag("DIGEST"), "digest", int.class, getDigest("SHA_2_256"));
        Object algorithm = createKeyParameter(getTag("ALGORITHM"), "algorithm", int.class, getAlgorithm("EC"));
        return newKeyParameterArray(purpose, digest, algorithm);
    }

    public static Object createKeyParameter(int tag, String valueFactoryMethod, Class<?> valueType, Object value)
            throws Exception {
        Class<?> keyParameterClass = Class.forName("android.hardware.security.keymint.KeyParameter");
        Class<?> keyParameterValueClass = Class.forName("android.hardware.security.keymint.KeyParameterValue");
        Object keyParameter = keyParameterClass.getDeclaredConstructor().newInstance();
        Method factoryMethod = keyParameterValueClass.getMethod(valueFactoryMethod, valueType);
        Object keyParameterValue = factoryMethod.invoke(null, value);

        Field tagField = keyParameterClass.getField("tag");
        tagField.setInt(keyParameter, tag);

        Field valueField = keyParameterClass.getField("value");
        valueField.set(keyParameter, keyParameterValue);
        return keyParameter;
    }

    public static Object newKeyParameterArray(Object... keyParameters) throws Exception {
        Class<?> keyParameterClass = Class.forName("android.hardware.security.keymint.KeyParameter");
        Object array = Array.newInstance(keyParameterClass, keyParameters.length);
        for (int i = 0; i < keyParameters.length; i++) {
            Array.set(array, i, keyParameters[i]);
        }
        return array;
    }

    public static Object getMetadata(Object keyEntryResponse) throws Exception {
        return getFieldValue(keyEntryResponse, "metadata");
    }

    public static Object getReturnedKeyDescriptor(Object keyEntryResponse) throws Exception {
        return getFieldValue(getMetadata(keyEntryResponse), "key");
    }

    public static Object getOperationBinder(Object createOperationResponse) throws Exception {
        return getFieldValue(createOperationResponse, "iOperation");
    }

    public static Object getSecurityLevelBinder(Object keyEntryResponse) throws Exception {
        return getFieldValue(keyEntryResponse, "iSecurityLevel");
    }

    public static Object getFieldValue(Object instance, String fieldName) throws Exception {
        if (instance == null) {
            return null;
        }
        Field field = instance.getClass().getField(fieldName);
        return field.get(instance);
    }

    public static int getIntField(Object instance, String fieldName) throws Exception {
        Field field = instance.getClass().getField(fieldName);
        return field.getInt(instance);
    }

    public static long getLongField(Object instance, String fieldName) throws Exception {
        Field field = instance.getClass().getField(fieldName);
        return field.getLong(instance);
    }

    public static String getStringField(Object instance, String fieldName) throws Exception {
        Field field = instance.getClass().getField(fieldName);
        Object value = field.get(instance);
        return value == null ? null : value.toString();
    }

    public static Object[] toObjectArray(Object array) {
        if (array == null) {
            return new Object[0];
        }

        int length = Array.getLength(array);
        Object[] result = new Object[length];
        for (int i = 0; i < length; i++) {
            result[i] = Array.get(array, i);
        }
        return result;
    }

    public static int getDomainApp() {
        return getStaticIntField("android.system.keystore2.Domain", "APP", DOMAIN_APP);
    }

    public static int getDomainKeyId() {
        return getStaticIntField("android.system.keystore2.Domain", "KEY_ID", DOMAIN_KEY_ID);
    }

    public static int getSecurityLevelTrustedEnvironment() {
        return getStaticIntField(
                "android.hardware.security.keymint.SecurityLevel",
                "TRUSTED_ENVIRONMENT",
                SECURITY_LEVEL_TRUSTED_ENVIRONMENT);
    }

    public static int getTag(String fieldName) {
        return getStaticIntField("android.hardware.security.keymint.Tag", fieldName, Integer.MIN_VALUE);
    }

    public static int getKeyPurpose(String fieldName) {
        return getStaticIntField("android.hardware.security.keymint.KeyPurpose", fieldName, Integer.MIN_VALUE);
    }

    public static int getDigest(String fieldName) {
        return getStaticIntField("android.hardware.security.keymint.Digest", fieldName, Integer.MIN_VALUE);
    }

    public static int getAlgorithm(String fieldName) {
        return getStaticIntField("android.hardware.security.keymint.Algorithm", fieldName, Integer.MIN_VALUE);
    }

    public static int getInvalidOperationHandleError() {
        return getStaticIntField(
                "android.hardware.security.keymint.ErrorCode",
                "INVALID_OPERATION_HANDLE",
                KM_ERROR_INVALID_OPERATION_HANDLE);
    }

    public static int getTooMuchDataResponseCode() {
        return getStaticIntField("android.system.keystore2.ResponseCode", "TOO_MUCH_DATA", RESPONSE_CODE_TOO_MUCH_DATA);
    }

    public static Throwable unwrapThrowable(Throwable throwable) {
        Throwable current = throwable;
        while (current instanceof InvocationTargetException && current.getCause() != null) {
            current = current.getCause();
        }
        return current;
    }

    public static boolean isServiceSpecificException(Throwable throwable) {
        Throwable unwrapped = unwrapThrowable(throwable);
        return unwrapped != null
                && "android.os.ServiceSpecificException"
                        .equals(unwrapped.getClass().getName());
    }

    public static int getServiceSpecificErrorCode(Throwable throwable) {
        Throwable unwrapped = unwrapThrowable(throwable);
        if (isServiceSpecificException(unwrapped)) {
            try {
                Field errorCodeField = unwrapped.getClass().getField("errorCode");
                return errorCodeField.getInt(unwrapped);
            } catch (Throwable ignored) {
                return Integer.MIN_VALUE;
            }
        }
        return Integer.MIN_VALUE;
    }

    public static String describeThrowable(Throwable throwable) {
        Throwable unwrapped = unwrapThrowable(throwable);
        return unwrapped.getClass().getName() + ": " + unwrapped.getMessage();
    }

    private static int getStaticIntField(String className, String fieldName, int fallback) {
        try {
            Class<?> clazz = Class.forName(className);
            Field field = clazz.getField(fieldName);
            return field.getInt(null);
        } catch (Throwable t) {
            Log.w(TAG, "Falling back for " + className + "." + fieldName + ": " + t.getMessage());
            return fallback;
        }
    }
}
