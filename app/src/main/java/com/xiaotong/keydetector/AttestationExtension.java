package com.xiaotong.keydetector;

import static com.xiaotong.keydetector.Constant.KEY_ATTESTATION_OID;

import java.io.IOException;
import java.security.cert.X509Certificate;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;

public class AttestationExtension {
    private Integer attestationVersion;
    private Integer attestationSecurityLevel;
    private Integer keymasterVersion;
    private Integer keymasterSecurityLevel;
    private byte[] attestationChallenge;
    private byte[] uniqueId;

    public static final int KM_SECURITY_LEVEL_SOFTWARE = 0;
    public static final int KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT = 1;
    public static final int KM_SECURITY_LEVEL_STRONG_BOX = 2;

    private AttestationExtension() {}

    public Integer getAttestationVersion() {
        return attestationVersion;
    }

    public Integer getAttestationSecurityLevel() {
        return attestationSecurityLevel;
    }

    public Integer getKeymasterVersion() {
        return keymasterVersion;
    }

    public Integer getKeymasterSecurityLevel() {
        return keymasterSecurityLevel;
    }

    public byte[] getAttestationChallenge() {
        return attestationChallenge;
    }

    public byte[] getUniqueId() {
        return uniqueId;
    }

    public static AttestationExtension parse(X509Certificate leafCert) {
        byte[] ext = leafCert.getExtensionValue(KEY_ATTESTATION_OID);
        if (ext == null) return null;

        try {
            ASN1OctetString octet = (ASN1OctetString) ASN1Primitive.fromByteArray(ext);
            ASN1Sequence attestation = (ASN1Sequence) ASN1Primitive.fromByteArray(octet.getOctets());

            if (attestation.size() < 6) {
                return null;
            }

            AttestationExtension result = new AttestationExtension();

            result.attestationVersion = getIntegerFromAsn1(attestation.getObjectAt(0));

            result.attestationSecurityLevel = getIntegerFromAsn1(attestation.getObjectAt(1));

            result.keymasterVersion = getIntegerFromAsn1(attestation.getObjectAt(2));

            result.keymasterSecurityLevel = getIntegerFromAsn1(attestation.getObjectAt(3));

            result.attestationChallenge = getOctetStringFromAsn1(attestation.getObjectAt(4));

            result.uniqueId = getOctetStringFromAsn1(attestation.getObjectAt(5));

            return result;
        } catch (IOException e) {
            return null;
        }
    }

    private static Integer getIntegerFromAsn1(ASN1Encodable asn1Value) {
        try {
            if (asn1Value instanceof ASN1Integer) {
                return ((ASN1Integer) asn1Value).getValue().intValue();
            }
            return null;
        } catch (Exception e) {
            return null;
        }
    }

    private static byte[] getOctetStringFromAsn1(ASN1Encodable asn1Value) {
        try {
            if (asn1Value instanceof ASN1OctetString) {
                return ((ASN1OctetString) asn1Value).getOctets();
            }
            return null;
        } catch (Exception e) {
            return null;
        }
    }

    public static String securityLevelToString(int level) {
        switch (level) {
            case KM_SECURITY_LEVEL_SOFTWARE:
                return "Software";
            case KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT:
                return "TEE";
            case KM_SECURITY_LEVEL_STRONG_BOX:
                return "StrongBox";
            default:
                return "Unknown (" + level + ")";
        }
    }

    @Override
    public String toString() {
        return "AttestationExtension{" + "attestationVersion="
                + attestationVersion + ", attestationSecurityLevel="
                + securityLevelToString(attestationSecurityLevel != null ? attestationSecurityLevel : -1)
                + ", keymasterVersion="
                + keymasterVersion + ", keymasterSecurityLevel="
                + securityLevelToString(keymasterSecurityLevel != null ? keymasterSecurityLevel : -1) + '}';
    }
}
