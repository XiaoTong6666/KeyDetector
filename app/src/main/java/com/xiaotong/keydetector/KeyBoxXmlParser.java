package com.xiaotong.keydetector;

import android.util.Base64;
import android.util.Xml;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.sec.ECPrivateKey;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;

public class KeyBoxXmlParser {
    private final XmlPullParser parser;
    private final CertificateFactory certificateFactory;
    private final List<Certificate> chain = new ArrayList<>();
    private PrivateKey privateKey = null;

    public KeyBoxXmlParser() {
        try {
            parser = Xml.newPullParser();
            certificateFactory = CertificateFactory.getInstance("X.509");
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        }
    }

    public KeyStore.PrivateKeyEntry parse(String keybox) throws IOException {
        try {
            parser.setInput(new StringReader(keybox));
            chain.clear();
            privateKey = null;
            readAndroidAttestation();
        } catch (XmlPullParserException e) {
            throw new IOException(e);
        }
        if (privateKey == null || chain.isEmpty()) {
            throw new IOException("No key found");
        }
        return new KeyStore.PrivateKeyEntry(privateKey, chain.toArray(new Certificate[0]));
    }

    private void readAndroidAttestation() throws XmlPullParserException, IOException {
        while (parser.next() != XmlPullParser.END_DOCUMENT) {
            if (parser.getEventType() != XmlPullParser.START_TAG) {
                continue;
            }
            String name = parser.getName();
            String algorithm = parser.getAttributeValue(null, "algorithm");
            if ("Key".equals(name) && "ecdsa".equals(algorithm)) {
                parser.nextTag();
                readECKey();
                break;
            }
        }
    }

    private void readECKey() throws XmlPullParserException, IOException {
        while (!(parser.getEventType() == XmlPullParser.END_TAG && "Key".equals(parser.getName()))) {
            if (parser.getEventType() != XmlPullParser.START_TAG) {
                parser.next();
                continue;
            }
            String format = parser.getAttributeValue(null, "format");
            String name = parser.getName();

            if ("PrivateKey".equals(name)) {
                if ("pem".equals(format)) {
                    parser.next();
                    readPrivateKey(parser.getText());
                    parser.next();
                } else {
                    return;
                }
            } else if ("Certificate".equals(name)) {
                if ("pem".equals(format)) {
                    parser.next();
                    readCertificateChain(parser.getText());
                    parser.next();
                } else {
                    return;
                }
            } else {
                parser.next();
            }
        }
    }

    private void readPrivateKey(String text) throws IOException {
        try {
            ASN1Sequence sequence = ASN1Sequence.getInstance(stringToBytes(text));
            ECPrivateKey ecKey = ECPrivateKey.getInstance(sequence);
            AlgorithmIdentifier id =
                    new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, ecKey.getParametersObject());
            byte[] data = new PrivateKeyInfo(id, ecKey).getEncoded();
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(data);
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            privateKey = keyFactory.generatePrivate(keySpec);
        } catch (GeneralSecurityException e) {
            throw new IOException(e);
        }
    }

    private byte[] stringToBytes(String text) {
        StringBuilder sb = new StringBuilder();
        String[] lines = text.split("\\r?\\n");

        for (String s : lines) {
            String line = s.trim();
            if (line.isEmpty()) continue;
            if (line.startsWith("-")) continue;
            sb.append(line);
        }
        return Base64.decode(sb.toString(), Base64.DEFAULT);
    }

    private void readCertificateChain(String text) throws IOException {
        try {
            ByteArrayInputStream data = new ByteArrayInputStream(stringToBytes(text));
            chain.add(certificateFactory.generateCertificate(data));
        } catch (CertificateException e) {
            throw new IOException(e);
        }
    }
}
