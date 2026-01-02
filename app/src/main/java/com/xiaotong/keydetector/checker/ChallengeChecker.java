package com.xiaotong.keydetector.checker;

import static com.xiaotong.keydetector.Constant.KEY_ATTESTATION_OID;

import com.xiaotong.keydetector.CheckerContext;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;

import java.security.cert.X509Certificate;
import java.util.Arrays;

public final class ChallengeChecker extends Checker {
    @Override
    public String name() {
        return this.getClass().getName();
    }

    @Override
    public boolean check(CheckerContext ctx) throws Exception{
        final X509Certificate leafCert = ctx.certChain.get(0);
        final byte[] extBytes = leafCert.getExtensionValue(KEY_ATTESTATION_OID);
        if (extBytes == null) return false;
        ASN1InputStream ais = new ASN1InputStream(extBytes);
        ASN1OctetString octet = (ASN1OctetString) ais.readObject();
        ais.close();
        ais = new ASN1InputStream(octet.getOctets());
        ASN1Sequence seq = (ASN1Sequence) ais.readObject();
        ais.close();
        ASN1OctetString challengeOctet = (ASN1OctetString) seq.getObjectAt(4);
        byte[] certChallenge = challengeOctet.getOctets();
        return !Arrays.equals(ctx.challenge, certChallenge);
    }

    @Override
    public String description() {
        return "Attestation Challenge Mismatch (%d)\nAttestation Challenge 不匹配（可能重放）";
    }
}
