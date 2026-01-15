package com.xiaotong.keydetector;

import static com.xiaotong.keydetector.Constant.KEY_ATTESTATION_OID;
import static com.xiaotong.keydetector.Util.byteArrayToHexString;

import androidx.annotation.NonNull;
import java.io.IOException;
import java.security.cert.X509Certificate;
import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;

public class RootOfTrust {
    byte[] verifiedBootKey;
    Boolean deviceLocked;
    Integer verifiedBootState;
    byte[] verifiedBootHash;
    private boolean fromTeeEnforced;

    public byte[] getVerifiedBootKey() {
        return verifiedBootKey;
    }

    public Boolean getDeviceLocked() {
        return deviceLocked;
    }

    public Integer getVerifiedBootState() {
        return verifiedBootState;
    }

    public byte[] getVerifiedBootHash() {
        return verifiedBootHash;
    }

    public boolean isFromTeeEnforced() {
        return fromTeeEnforced;
    }

    private RootOfTrust(
            byte[] verifiedBootKey,
            Boolean deviceLocked,
            Integer verifiedBootState,
            byte[] verifiedBootHash,
            boolean fromTeeEnforced) {
        this.verifiedBootKey = verifiedBootKey;
        this.deviceLocked = deviceLocked;
        this.verifiedBootState = verifiedBootState;
        this.verifiedBootHash = verifiedBootHash;
        this.fromTeeEnforced = fromTeeEnforced;
    }

    public static RootOfTrust parse(X509Certificate leafCert) {
        byte[] ext = leafCert.getExtensionValue(KEY_ATTESTATION_OID);
        if (ext == null) return null;

        try {
            ASN1OctetString octet = (ASN1OctetString) ASN1Primitive.fromByteArray(ext);
            ASN1Sequence attestation = (ASN1Sequence) ASN1Primitive.fromByteArray(octet.getOctets());

            if (attestation.size() > 7) {
                ASN1Sequence teeEnforced = (ASN1Sequence) attestation.getObjectAt(7);
                RootOfTrust rot = extractRootOfTrust(teeEnforced, true);
                if (rot != null) {
                    return rot;
                }
            }

            if (attestation.size() > 6) {
                ASN1Sequence softwareEnforced = (ASN1Sequence) attestation.getObjectAt(6);
                RootOfTrust rot = extractRootOfTrust(softwareEnforced, false);
                if (rot != null) {
                    return rot;
                }
            }

            return null;
        } catch (IOException e) {
            return null;
        }
    }

    private static RootOfTrust extractRootOfTrust(ASN1Sequence sequence, boolean fromTee) {
        try {
            for (ASN1Encodable e : sequence) {
                if (!(e instanceof ASN1TaggedObject)) {
                    continue;
                }

                ASN1TaggedObject tagged = (ASN1TaggedObject) e;
                if (tagged.getTagNo() == 704) {
                    ASN1Sequence seq = ASN1Sequence.getInstance(tagged.getBaseObject());

                    if (seq.size() < 3) {
                        return null;
                    }

                    byte[] verifiedBootKey = ((ASN1OctetString) seq.getObjectAt(0)).getOctets();
                    boolean deviceLocked = ((ASN1Boolean) seq.getObjectAt(1)).isTrue();
                    int verifiedBootState =
                            ((ASN1Enumerated) seq.getObjectAt(2)).getValue().intValue();

                    byte[] verifiedBootHash = null;
                    if (seq.size() >= 4) {
                        verifiedBootHash = ((ASN1OctetString) seq.getObjectAt(3)).getOctets();
                    }

                    return new RootOfTrust(verifiedBootKey, deviceLocked, verifiedBootState, verifiedBootHash, fromTee);
                }
            }
        } catch (Exception ex) {
            // return null
        }
        return null;
    }

    @NonNull
    public String toString() {
        return "RootOfTrust{"
                + "verifiedBootKey="
                + byteArrayToHexString(verifiedBootKey)
                + ", deviceLocked="
                + deviceLocked
                + ", verifiedBootState="
                + verifiedBootState
                + ", verifiedBootHash="
                + byteArrayToHexString(verifiedBootHash)
                + ", fromTeeEnforced="
                + fromTeeEnforced
                + '}';
    }
}
