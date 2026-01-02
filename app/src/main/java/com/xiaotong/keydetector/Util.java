package com.xiaotong.keydetector;

import static com.xiaotong.keydetector.Constant.GOOGLE_ROOT_F;
import static com.xiaotong.keydetector.Constant.GOOGLE_ROOT_G;
import static com.xiaotong.keydetector.Constant.GOOGLE_ROOT_H;
import static com.xiaotong.keydetector.Constant.GOOGLE_ROOT_I;
import static com.xiaotong.keydetector.Constant.KEYSTORE_PROVIDER;
import static com.xiaotong.keydetector.Constant.KEY_ALIAS;
import static com.xiaotong.keydetector.Constant.ROOT_AOSP;
import static com.xiaotong.keydetector.Constant.ROOT_GOOGLE_F;
import static com.xiaotong.keydetector.Constant.ROOT_GOOGLE_I;
import static com.xiaotong.keydetector.Constant.ROOT_UNKNOWN;
import static com.xiaotong.keydetector.Constant.ROOT_VENDOR_REQUIRED;
import static com.xiaotong.keydetector.Constant.VENDOR_REQUIRED_ROOT_PUBLIC_KEYS_B64;

import android.annotation.SuppressLint;
import android.content.Context;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.lsposed.hiddenapibypass.HiddenApiBypass;

import java.io.ByteArrayInputStream;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

public class Util {
    public static int classifyRootType(X509Certificate rootCert) {
        if (rootCert == null) return ROOT_UNKNOWN;
        byte[] key = rootCert.getPublicKey().getEncoded();
        if (Arrays.equals(key, GOOGLE_ROOT_F)) return ROOT_GOOGLE_F;
        if (Arrays.equals(key, GOOGLE_ROOT_G) || Arrays.equals(key, GOOGLE_ROOT_H)) return ROOT_AOSP;
        if (Arrays.equals(key, GOOGLE_ROOT_I)) return ROOT_GOOGLE_I;
        String keyB64 = Base64.encodeToString(key, Base64.NO_WRAP);
        return VENDOR_REQUIRED_ROOT_PUBLIC_KEYS_B64.contains(keyB64) ? ROOT_VENDOR_REQUIRED : ROOT_UNKNOWN;
    }

    @SuppressLint("PrivateApi")
    public static String getSystemProperty(String key) {
        try {
             Class<?> c = Class.forName("android.os.SystemProperties");
            Method m = c.getDeclaredMethod("get", String.class);
            return (String) m.invoke(null, key);
        } catch (Exception e) { return null; }
    }

    public static byte[] hexStringToByteArray(String hex) {
        if (hex == null) throw new IllegalArgumentException("hex string is null");
        String s = hex.trim();
        if ((s.length() & 1) != 0) throw new IllegalArgumentException("hex string must have even length: " + s.length());
        int len = s.length();
        byte[] out = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            int hi = Character.digit(s.charAt(i), 16);
            int lo = Character.digit(s.charAt(i + 1), 16);
            if (hi == -1 || lo == -1) throw new IllegalArgumentException("invalid hex char at position " + i);
            out[i / 2] = (byte) ((hi << 4) | lo);
        }
        return out;
    }

    public static String byteArrayToHexString(byte[] data) {
        if (data == null) throw new IllegalArgumentException("byte array is null");
        char[] out = new char[data.length * 2];
        final char[] HEX = "0123456789abcdef".toCharArray();
        int i = 0;
        for (byte b : data) {
            int v = b & 0xFF;
            out[i++] = HEX[v >>> 4];
            out[i++] = HEX[v & 0x0F];
        }
        return new String(out);
    }

    static CheckerContext getCheckerContext(Context appContext) {
        Security.removeProvider("BC");
        if (Security.getProvider("BC") == null) Security.addProvider(new BouncyCastleProvider());
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                HiddenApiBypass.addHiddenApiExemptions("");
            }
        } catch (Throwable t) {
            Log.w("Util", "HiddenApiBypass failed", t);
        }
        try {
            KeyStore keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER);
            keyStore.load(null);
            try {
                if (keyStore.containsAlias(KEY_ALIAS)) keyStore.deleteEntry(KEY_ALIAS);
            } catch (Exception ignored) { }
            byte[] challenge = java.util.UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8);
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, KEYSTORE_PROVIDER);
            KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_SIGN)
                    .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setCertificateNotBefore(new Date())
                    .setAttestationChallenge(challenge);
            if (Build.VERSION.SDK_INT >= 31) builder.setAttestKeyAlias(null);
            keyPairGenerator.initialize(builder.build());
            keyPairGenerator.generateKeyPair();
            keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER);
            keyStore.load(null);
            Certificate[] rawChain = keyStore.getCertificateChain(KEY_ALIAS);
            if (rawChain == null || rawChain.length < 2) return null;
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            List<X509Certificate> sanitizedChain = new ArrayList<>();
            for (Certificate c : rawChain) {
                sanitizedChain.add((X509Certificate) cf.generateCertificate(
                        new ByteArrayInputStream(c.getEncoded())));
            }
            return new CheckerContext(appContext, keyStore, sanitizedChain, challenge);
        } catch (Throwable t) {
            return null;
        }
    }

    public static byte[] randomChallenge(int size) {
        byte[] challenge = new byte[size];
        new SecureRandom().nextBytes(challenge);
        return challenge;
    }
}
