package com.xiaotong.keydetector;

import android.annotation.SuppressLint;
import android.content.res.Resources;
import android.util.Base64;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Set;

public class Constant {
    public static final String KEY_ALIAS = "PoC_Attest_Key";
    public static final String KEYSTORE_PROVIDER = "AndroidKeyStore";
    public static final String KEY_ATTESTATION_OID = "1.3.6.1.4.1.11129.2.1.17";
    public static final int RESULT_TRUSTED = 1;
    public static final int RESULT_PATCH_MODE = 512;
    public static final int ROOT_UNKNOWN = 0;
    public static final int ROOT_AOSP = 1;
    public static final int ROOT_GOOGLE_F = 2;
    public static final int ROOT_GOOGLE_I = 3;
    public static final int ROOT_VENDOR_REQUIRED = 4;

    public static final byte[] GOOGLE_ROOT_F = Base64.decode(
            "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xUFmOr75gvMsd/dTEDDJdSSxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5jlRfdnJLmN0pTy/4lj4/7tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y//0rb+T+W8a9nsNL/ggjnar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73XpXyTqRxB/M0n1n/W9nGqC4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYImQQcHtGl/m00QLVWutHQoVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB+TxywElgS70vE0XmLD+OJtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7quvmag8jfPioyKvxnK/EgsTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgpZrt3i5MIlCaY504LzSRiigHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7gLiMm0jhO2B6tUXHI/+MRPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82ixPvZtXQpUpuL12ab+9EaDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR/bkwSWc+NpUFgNPN9PvQi8WEg5UmAGMCAwEAAQ==", 0);
    public static final byte[] GOOGLE_ROOT_G = Base64.decode(
            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7l1ex+HA220Dpn7mthvsTWpdamguD/9/SQ59dx9EIm29sa/6FsvHrcV30lacqrewLVQBXT5DKyqO107sSHVBpA==", 0);
    public static final byte[] GOOGLE_ROOT_H = Base64.decode(
            "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCia63rbi5EYe/VDoLmt5TRdSMfd5tjkWP/96r/C3JHTsAsQ+wzfNes7UA+jCigZtX3hwszl94OuE4TQKuvpSe/lWmgMdsGUmX4RFlXYfC78hdLt0GAZMAoDo9Sd47b0ke2RekZyOmLw9vCkT/X11DEHTVm+Vfkl5YLCazOkjWFmwIDAQAB", 0);
    public static final byte[] GOOGLE_ROOT_I = Base64.decode(
            "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBhbGuLrpql5I2WJmrE5kEVZOo+dgA46mKrVJf/sgzfzs2u7M9c1Y9ZkCEiiYkhTFE9vPbasmUfXybwgZ2EM30A1ABPd124n3JbEDfsB/wnMH1AcgsJyJFPbETZiy42Fhwi+2BCA5bcHe7SrdkRIYSsdBRaKBoZsapxB0gAOs0jSPRX5M=", 0);
    public static final Set<String> VENDOR_REQUIRED_ROOT_PUBLIC_KEYS_B64 = new HashSet<>();
    static {
        try {
            Resources resources = Resources.getSystem();
            @SuppressLint("DiscouragedApi")
            int id = resources.getIdentifier("vendor_required_attestation_certificates", "array", "android");
            if (id != 0) {
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                for (String raw : resources.getStringArray(id)) {
                    String normalized = raw
                            .replaceAll("\\s+", "\n")
                            .replaceAll("-BEGIN\\nCERTIFICATE-", "-BEGIN CERTIFICATE-")
                            .replaceAll("-END\\nCERTIFICATE-", "-END CERTIFICATE-");
                    X509Certificate cert = (X509Certificate) cf.generateCertificate(
                            new ByteArrayInputStream(normalized.getBytes(StandardCharsets.UTF_8)));
                    VENDOR_REQUIRED_ROOT_PUBLIC_KEYS_B64.add(
                            Base64.encodeToString(cert.getPublicKey().getEncoded(), Base64.NO_WRAP));
                }
            }
        } catch (Throwable ignored) {
        }
    }
}
