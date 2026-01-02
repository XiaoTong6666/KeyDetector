package com.xiaotong.keydetector.checker;

import static com.xiaotong.keydetector.Constant.KEY_ALIAS;

import com.xiaotong.keydetector.CheckerContext;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;

public final class KeyConsistencyChecker extends Checker{
    @Override
    public String name() {
        return this.getClass().getName();
    }

    @Override
    public boolean check(CheckerContext ctx) throws Exception {
        KeyStore.Entry entry = ctx.keyStore.getEntry(KEY_ALIAS, null);
        if (!(entry instanceof KeyStore.PrivateKeyEntry)) throw new Exception("Entry is not a PrivateKeyEntry");
        PrivateKey privateKey = ((KeyStore.PrivateKeyEntry) entry).getPrivateKey();
        PublicKey publicKey = ctx.certChain.get(0).getPublicKey();
        byte[] data = "ConsistencyCheck".getBytes(StandardCharsets.UTF_8);
        Signature signer = Signature.getInstance("SHA256withECDSA");
        signer.initSign(privateKey);
        signer.update(data);
        byte[] signature = signer.sign();
        java.security.Provider bcProvider = Security.getProvider("BC");
        if (bcProvider == null) bcProvider = new BouncyCastleProvider();
        Signature verifier = Signature.getInstance("SHA256withECDSA", bcProvider);
        verifier.initVerify(publicKey);
        verifier.update(data);
        return !verifier.verify(signature);
    }

    @Override
    public String description() {
        return "Key Mismatch (%d)\n私钥与证书公钥不匹配，严重的欺诈行为";
    }
}