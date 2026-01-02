package com.xiaotong.keydetector.handler;

import android.os.Build;
import android.os.IBinder;
import android.util.Log;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class BinderHookHandler {

    private static final String TAG = "BinderHook";

    public static byte[] sInterceptedCertificate = null;
    private static final ConcurrentHashMap<String, byte[]> sGenerateKeyLeafCertsByAlias = new ConcurrentHashMap<>();
    private static final ConcurrentHashMap<String, byte[]> sGenerateKeyChainBlobsByAlias = new ConcurrentHashMap<>();
    private static final ConcurrentHashMap<String, byte[]> sGetKeyEntryLeafCertsByAlias = new ConcurrentHashMap<>();
    private static final ConcurrentHashMap<String, byte[]> sGetKeyEntryChainBlobsByAlias = new ConcurrentHashMap<>();
    private static final ConcurrentHashMap<String, byte[]> sLegacyGetByName = new ConcurrentHashMap<>();

    public static byte[] getGenerateKeyLeafCertificate(String alias) {
        return alias == null ? null : sGenerateKeyLeafCertsByAlias.get(alias);
    }

    public static byte[] getGenerateKeyCertificateChainBlob(String alias) {
        return alias == null ? null : sGenerateKeyChainBlobsByAlias.get(alias);
    }

    public static byte[] getKeyEntryLeafCertificate(String alias) {
        return alias == null ? null : sGetKeyEntryLeafCertsByAlias.get(alias);
    }

    public static byte[] getKeyEntryCertificateChainBlob(String alias) {
        return alias == null ? null : sGetKeyEntryChainBlobsByAlias.get(alias);
    }

    public static byte[] getLegacyKeystoreBlob(String name) {
        return name == null ? null : sLegacyGetByName.get(name);
    }

    public static boolean installHook() {
        sInterceptedCertificate = null;
        sGenerateKeyLeafCertsByAlias.clear();
        sGenerateKeyChainBlobsByAlias.clear();
        sGetKeyEntryLeafCertsByAlias.clear();
        sGetKeyEntryChainBlobsByAlias.clear();
        sLegacyGetByName.clear();

        if (Build.VERSION.SDK_INT >= 31) {
            if (installKeystore2Hook()) {
                Log.d(TAG, "Keystore 2.0 Hook installed successfully.");
                return true;
            }
        }

        if (installLegacyKeystoreHook()) {
            Log.d(TAG, "Legacy Keystore Hook installed successfully.");
            return true;
        }

        Log.e(TAG, "Failed to install Binder Hook.");
        return false;
    }

    private static boolean installKeystore2Hook() {
        try {
            final String SERVICE_NAME = "android.system.keystore2.IKeystoreService/default";
            final String INTERFACE_NAME = "android.system.keystore2.IKeystoreService";
            final String PROXY_CLASS_NAME = "android.system.keystore2.IKeystoreService$Stub$Proxy";

            Class<?> smClass = Class.forName("android.os.ServiceManager");
            Field sCacheField = smClass.getDeclaredField("sCache");
            sCacheField.setAccessible(true);
            Map<String, IBinder> sCache = (Map<String, IBinder>) sCacheField.get(null);

            Method getServiceMethod = smClass.getMethod("getService", String.class);
            final IBinder originalBinder = (IBinder) getServiceMethod.invoke(null, SERVICE_NAME);

            if (originalBinder == null) return false;

            Class<?> iKeystoreServiceClass = Class.forName(INTERFACE_NAME);

            Class<?> stubProxyClass = Class.forName(PROXY_CLASS_NAME);
            Constructor<?> constructor = stubProxyClass.getDeclaredConstructor(IBinder.class);
            constructor.setAccessible(true);
            final Object realService = constructor.newInstance(originalBinder);

            Object proxyService = Proxy.newProxyInstance(
                    smClass.getClassLoader(),
                    new Class[]{iKeystoreServiceClass},
                    new Keystore2InvocationHandler(realService)
            );

            IBinder proxyBinder = (IBinder) Proxy.newProxyInstance(
                    smClass.getClassLoader(),
                    new Class[]{IBinder.class},
                    new BinderProxyHandler(originalBinder, proxyService, INTERFACE_NAME)
            );

            sCache.put(SERVICE_NAME, proxyBinder);
            return true;

        } catch (Throwable t) {
            Log.w(TAG, "Keystore2 Hook failed", t);
            return false;
        }
    }

    private static boolean installLegacyKeystoreHook() {
        try {
            final String SERVICE_NAME = "android.security.keystore";
            //android.security.IKeystoreService android.security.keystore.IKeystoreService
            String interfaceName = "android.security.keystore.IKeystoreService";
            String proxyClassName = "android.security.keystore.IKeystoreService$Stub$Proxy";

            try {
                Class.forName(interfaceName);
            } catch (ClassNotFoundException e) {
                interfaceName = "android.security.IKeystoreService";
                proxyClassName = "android.security.IKeystoreService$Stub$Proxy";
            }

            Class<?> smClass = Class.forName("android.os.ServiceManager");
            Field sCacheField = smClass.getDeclaredField("sCache");
            sCacheField.setAccessible(true);
            Map<String, IBinder> sCache = (Map<String, IBinder>) sCacheField.get(null);

            Method getServiceMethod = smClass.getMethod("getService", String.class);
            final IBinder originalBinder = (IBinder) getServiceMethod.invoke(null, SERVICE_NAME);

            if (originalBinder == null) return false;

            Class<?> iKeystoreServiceClass = Class.forName(interfaceName);
            Class<?> stubProxyClass = Class.forName(proxyClassName);
            Constructor<?> constructor = stubProxyClass.getDeclaredConstructor(IBinder.class);
            constructor.setAccessible(true);
            final Object realService = constructor.newInstance(originalBinder);

            Object proxyService = Proxy.newProxyInstance(
                    smClass.getClassLoader(),
                    new Class[]{iKeystoreServiceClass},
                    new LegacyKeystoreInvocationHandler(realService)
            );

            IBinder proxyBinder = (IBinder) Proxy.newProxyInstance(
                    smClass.getClassLoader(),
                    new Class[]{IBinder.class},
                    new BinderProxyHandler(originalBinder, proxyService, interfaceName)
            );

            sCache.put(SERVICE_NAME, proxyBinder);
            return true;

        } catch (Throwable t) {
            Log.w(TAG, "Legacy Keystore Hook failed", t);
            return false;
        }
    }

    private static class Keystore2InvocationHandler implements InvocationHandler {
        private final Object realService;

        public Keystore2InvocationHandler(Object service) {
            this.realService = service;
        }

        @Override
        public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
            final Object result;
            try {
                result = method.invoke(realService, args);
            } catch (InvocationTargetException e) {
                throw e.getCause();
            }

            final String methodName = method.getName();
            if ("getSecurityLevel".equals(methodName) && result != null) {
                final Object wrapped = wrapKeystore2SecurityLevelIfPossible(result);
                return wrapped != null ? wrapped : result;
            }

            if ("getKeyEntry".equals(methodName)) {
                final String alias = tryExtractAlias(args, 0);
                final byte[] leaf = tryExtractKeyEntryResponseLeafCertificate(result);
                final byte[] chainBlob = tryExtractKeyEntryResponseCertificateChainBlob(result);
                if (alias != null && leaf != null) {
                    sGetKeyEntryLeafCertsByAlias.put(alias, leaf);
                }
                if (alias != null && chainBlob != null) {
                    sGetKeyEntryChainBlobsByAlias.put(alias, chainBlob);
                }
            }

            if ("generateKey".equals(methodName)) {
                final String alias = tryExtractAlias(args, 0);
                final byte[] leaf = tryGetByteArrayField(result, "certificate");
                final byte[] chainBlob = tryGetByteArrayField(result, "certificateChain");
                if (alias != null && leaf != null) {
                    sGenerateKeyLeafCertsByAlias.put(alias, leaf);
                    sInterceptedCertificate = leaf;
                }
                if (alias != null && chainBlob != null) {
                    sGenerateKeyChainBlobsByAlias.put(alias, chainBlob);
                }
            }

            return result;
        }
    }

    private static class KeyMintSecurityLevelInvocationHandler implements InvocationHandler {
        private final Object realService;

        public KeyMintSecurityLevelInvocationHandler(Object service) {
            this.realService = service;
        }

        @Override
        public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
            final Object result;
            try {
                result = method.invoke(realService, args);
            } catch (InvocationTargetException e) {
                throw e.getCause();
            }

            if ("generateKey".equals(method.getName())) {
                final String alias = tryExtractAlias(args, 0);
                final byte[] leaf = tryGetByteArrayField(result, "certificate");
                final byte[] chainBlob = tryGetByteArrayField(result, "certificateChain");
                if (alias != null && leaf != null) {
                    sGenerateKeyLeafCertsByAlias.put(alias, leaf);
                    sInterceptedCertificate = leaf;
                }
                if (alias != null && chainBlob != null) {
                    sGenerateKeyChainBlobsByAlias.put(alias, chainBlob);
                }
            }
            return result;
        }
    }

    private static Object wrapKeystore2SecurityLevelIfPossible(Object securityLevel) {
        try {
            Class<?> securityLevelInterface = Class.forName("android.system.keystore2.IKeystoreSecurityLevel");
            if (!securityLevelInterface.isInstance(securityLevel)) {
                return null;
            }
            return Proxy.newProxyInstance(
                    securityLevelInterface.getClassLoader(),
                    new Class[]{securityLevelInterface},
                    new KeyMintSecurityLevelInvocationHandler(securityLevel)
            );
        } catch (Throwable t) {
            Log.w(TAG, "Failed to wrap IKeystoreSecurityLevel", t);
            return null;
        }
    }

    private static String tryExtractAlias(Object[] args, int index) {
        if (args == null || args.length <= index) return null;
        Object keyDescriptor = args[index];
        if (keyDescriptor == null) return null;
        try {
            Field aliasField = keyDescriptor.getClass().getField("alias");
            Object v = aliasField.get(keyDescriptor);
            return v instanceof String ? (String) v : null;
        } catch (Throwable ignored) {
            return null;
        }
    }

    private static byte[] tryExtractKeyEntryResponseLeafCertificate(Object keyEntryResponse) {
        if (keyEntryResponse == null) return null;
        try {
            Object metadata = getFieldValue(keyEntryResponse, "metadata");
            return tryGetByteArrayField(metadata, "certificate");
        } catch (Throwable ignored) {
            return null;
        }
    }

    private static byte[] tryExtractKeyEntryResponseCertificateChainBlob(Object keyEntryResponse) {
        if (keyEntryResponse == null) return null;
        try {
            Object metadata = getFieldValue(keyEntryResponse, "metadata");
            return tryGetByteArrayField(metadata, "certificateChain");
        } catch (Throwable ignored) {
            return null;
        }
    }

    private static Object getFieldValue(Object obj, String fieldName) throws NoSuchFieldException, IllegalAccessException {
        Field f = obj.getClass().getField(fieldName);
        return f.get(obj);
    }

    private static byte[] tryGetByteArrayField(Object obj, String fieldName) {
        if (obj == null) return null;
        try {
            Field f = obj.getClass().getField(fieldName);
            Object v = f.get(obj);
            return v instanceof byte[] ? (byte[]) v : null;
        } catch (Throwable ignored) {
            return null;
        }
    }
    private static class LegacyKeystoreInvocationHandler implements InvocationHandler {
        private final Object realService;

        public LegacyKeystoreInvocationHandler(Object service) {
            this.realService = service;
        }

        @Override
        public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
            final Object result;
            try {
                result = method.invoke(realService, args);
            } catch (InvocationTargetException e) {
                throw e.getCause();
            }

            if ("get".equals(method.getName())
                    && result instanceof byte[]
                    && args != null
                    && args.length > 0
                    && args[0] instanceof String) {
                sLegacyGetByName.put((String) args[0], (byte[]) result);
            }
            return result;
        }
    }

    private static class BinderProxyHandler implements InvocationHandler {
        private final IBinder realBinder;
        private final Object proxyService;
        private final String interfaceDescriptor;

        public BinderProxyHandler(IBinder real, Object proxy, String descriptor) {
            this.realBinder = real;
            this.proxyService = proxy;
            this.interfaceDescriptor = descriptor;
        }

        @Override
        public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
            String methodName = method.getName();

            if ("queryLocalInterface".equals(methodName)) {
                return proxyService;
            } else if ("getInterfaceDescriptor".equals(methodName)) {
                return interfaceDescriptor;
            }

            return method.invoke(realBinder, args);
        }
    }
}
