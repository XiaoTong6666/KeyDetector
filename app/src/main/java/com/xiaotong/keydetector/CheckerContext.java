package com.xiaotong.keydetector;

import static com.xiaotong.keydetector.Util.classifyRootType;

import android.content.Context;

import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.List;

public class CheckerContext {

    public Context appContext;
    public KeyStore keyStore;

    // certs
    public List<X509Certificate> certChain;
    public int rootType;
    public byte[] challenge;

    public CheckerContext(Context appContext, KeyStore keyStore, List<X509Certificate> certChain, byte[] challenge) {
        if (certChain == null || certChain.isEmpty()) throw new IllegalArgumentException("CertChain is null or empty");
        this.appContext = appContext;
        this.keyStore = keyStore;
        this.certChain = certChain;
        this.rootType = classifyRootType(this.certChain.get(certChain.size() - 1));
        this.challenge = challenge;
    }
}

