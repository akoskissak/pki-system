package com.ftn.bsep.pki.service;

import com.ftn.bsep.pki.config.KeyStoreConfig;
import com.ftn.bsep.pki.entity.Issuer;
import com.ftn.bsep.pki.entity.Subject;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.stereotype.Service;

import java.io.FileOutputStream;
import java.math.BigInteger;
import java.nio.file.*;
import java.security.*;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

@Service
public class KeyStoreService {
    private final KeyStoreConfig cfg;

    public KeyStoreService(KeyStoreConfig cfg) {
        this.cfg = cfg;
    }

    /**
     * Generiše i vraća X.509 sertifikat na osnovu datih podataka o vlasniku i izdavaocu.
     */
    public X509Certificate generateCertificate(Subject subject, Issuer issuer) throws Exception {
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider("BC")
                .build(issuer.getPrivateKey());

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuer.getX500Name(),
                subject.getSerialNumber(),
                subject.getStartDate(),
                subject.getEndDate(),
                subject.getX500Name(),
                subject.getPublicKey()
        );

        return new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(certBuilder.build(signer));
    }

    /**
     * Kreira PKCS12 fajl i snima self-signed sertifikat u njega.
     */
    public Path saveCertificate(X509Certificate cert, PrivateKey privateKey, String alias, char[] password) throws Exception {
        Path dir = Paths.get(cfg.getCaDir());
        Files.createDirectories(dir);
        Path p12 = dir.resolve(alias + ".p12");

        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, password);
        ks.setKeyEntry(alias, privateKey, password, new X509Certificate[]{cert});

        try (FileOutputStream fos = new FileOutputStream(p12.toFile())) {
            ks.store(fos, password);
        }

        return p12;
    }
}
