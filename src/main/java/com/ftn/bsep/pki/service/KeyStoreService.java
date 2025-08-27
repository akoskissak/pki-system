package com.ftn.bsep.pki.service;

import com.ftn.bsep.pki.config.KeyStoreConfig;
import com.ftn.bsep.pki.entity.CertificateType;
import com.ftn.bsep.pki.entity.Issuer;
import com.ftn.bsep.pki.entity.Subject;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.stereotype.Service;

import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;

@Service
public class KeyStoreService {
    private final KeyStoreConfig cfg;

    public KeyStoreService(KeyStoreConfig cfg) {
        this.cfg = cfg;
    }

    public X509Certificate generateCertificate(
            Subject subject,
            Issuer issuer,
            CertificateType type,
            List<String> extensions
    ) throws Exception {
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider("BC")
                .build(issuer.getPrivateKey());

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuer.getX500Name(),
                subject.getSerialNumber(),
                subject.getStartDate(),
                subject.getEndDate(),
                subject.getX500Name(),
                SubjectPublicKeyInfo.getInstance(subject.getPublicKey().getEncoded())
        );

        int keyUsageFlags = 0;

        // Uvijek dodajemo BasicConstraints za CA sertifikate
        if (type == CertificateType.INTERMEDIATE || type == CertificateType.ROOT) {
            certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
            keyUsageFlags |= KeyUsage.keyCertSign;
            keyUsageFlags |= KeyUsage.cRLSign;
        }


        if (extensions != null) {
            for (String ext : extensions) {
                switch (ext) {
                    case "digitalSignature":
                        keyUsageFlags |= KeyUsage.digitalSignature;
                        break;
                    case "nonRepudiation":
                        keyUsageFlags |= KeyUsage.nonRepudiation;
                        break;
                    case "keyEncipherment":
                        keyUsageFlags |= KeyUsage.keyEncipherment;
                        break;
                    case "dataEncipherment":
                        keyUsageFlags |= KeyUsage.dataEncipherment;
                        break;
                    default:
                        System.err.println("Unrecognized extension: " + ext);
                }
            }
        }

        if (keyUsageFlags > 0) {
            certBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(keyUsageFlags));
        }

        return new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(certBuilder.build(signer));
    }

    public Path saveCertificateChain(
            X509Certificate[] chain,
            PrivateKey privateKey,
            String alias,
            char[] password
    ) throws Exception {
        Path dir = Paths.get(cfg.getCaDir());
        Files.createDirectories(dir);
        Path p12 = dir.resolve(alias + ".p12");

        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, password);

        ks.setKeyEntry(alias, privateKey, password, chain);

        try (FileOutputStream fos = new FileOutputStream(p12.toFile())) {
            ks.store(fos, password);
        }

        return p12;
    }

}