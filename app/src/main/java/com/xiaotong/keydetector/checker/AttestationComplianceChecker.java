package com.xiaotong.keydetector.checker;

import static com.xiaotong.keydetector.Util.randomChallenge;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import com.xiaotong.keydetector.CheckerContext;

import java.security.KeyPairGenerator;

public final class AttestationComplianceChecker extends Checker{
    private final static short CHALLENGE_LENGTH = 256;

    @Override
    public String name() {
        return this.getClass().getName();
    }

    @Override
    public boolean check(CheckerContext ctx) throws Exception {
        byte[] challenge = randomChallenge(CHALLENGE_LENGTH);
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_EC,
                    "AndroidKeyStore"
            );
            KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(
                    "attestation_test_256",
                    KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setAttestationChallenge(challenge)
                    .build();
            kpg.initialize(spec);
            kpg.generateKeyPair();
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public String description() {
        return "Non-compliant Keystore Detected (%d)\n检测到不规范的 KeyStore , Challenge 长度不应该允许为 " + Integer.toString(CHALLENGE_LENGTH);
    }
}