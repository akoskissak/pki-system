package com.ftn.bsep.pki.service;

import com.ftn.bsep.pki.config.KeyStoreConfig;
import com.ftn.bsep.pki.dto.SanDto;
import com.ftn.bsep.pki.entity.CertificateType;
import com.ftn.bsep.pki.entity.Issuer;
import com.ftn.bsep.pki.entity.Subject;
import org.bouncycastle.asn1.x509.*;
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
import java.util.ArrayList;
import java.util.List;

// Dodajte nove import-e za CDP


@Service
public class KeyStoreService {
    private final KeyStoreConfig cfg;

    public KeyStoreService(KeyStoreConfig cfg) {
        this.cfg = cfg;
    }

    public X509Certificate generateEECertificate(
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

        if (type == CertificateType.INTERMEDIATE || type == CertificateType.ROOT) {
            certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
            keyUsageFlags |= KeyUsage.keyCertSign;
            keyUsageFlags |= KeyUsage.cRLSign;
        } else if (type == CertificateType.END_ENTITY) {
            certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
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

        // 🆕 DODAVANJE CRL DISTRIBUTION POINT (CDP) EKSTENZIJE
        // Dinamički kreirajte URL za CRL (npr. koristite serijski broj izdavaoca)
        String crlUrl = cfg.getCrlBaseUrl() + "/" + issuer.getSerialNumber().toString() + ".crl";

        GeneralName gn = new GeneralName(GeneralName.uniformResourceIdentifier, crlUrl);
        DistributionPointName distPointName = new DistributionPointName(new GeneralNames(gn));
        DistributionPoint distPoint = new DistributionPoint(distPointName, null, null);
        CRLDistPoint crlDistPoint = new CRLDistPoint(new DistributionPoint[] { distPoint });

        // Dodavanje ekstenzije na sertifikat pre potpisivanja
        certBuilder.addExtension(Extension.cRLDistributionPoints, false, crlDistPoint);


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

    public Path saveEECertificate(X509Certificate certificate) {
        try {
            // Kreirajte folder za EE sertifikate ako ne postoji
            Path eeCertsDir = Paths.get(cfg.getEeDir());
            Files.createDirectories(eeCertsDir);

            // Napravite naziv datoteke na osnovu serijskog broja sertifikata
            String filename = certificate.getSerialNumber().toString() + ".cer";
            Path filePath = eeCertsDir.resolve(filename);

            // Zapisite certifikat u .DER formatu
            try (FileOutputStream fos = new FileOutputStream(filePath.toFile())) {
                fos.write(certificate.getEncoded());
            }

            System.out.println("✅ Saved EE certificate to: " + filePath);
            return filePath;

        } catch (Exception e) {
            throw new RuntimeException("Failed to save EE certificate.", e);
        }
    }
    public X509Certificate generateCertificate(
            Subject subject,
            Issuer issuer,
            CertificateType type,
            List<String> extensions,
            List<SanDto> subjectAlternativeNames
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

        // --- OBRADA EKSTENZIJA ---

        // 1. Basic Constraints
        if (type == CertificateType.INTERMEDIATE || type == CertificateType.ROOT) {
            certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        } else if (type == CertificateType.END_ENTITY) {
            certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        }

        // 2. Key Usage & Extended Key Usage
        int keyUsageFlags = 0;
        List<KeyPurposeId> ekuList = new ArrayList<>();

        // Obavezne ekstenzije za CA
        if (type == CertificateType.INTERMEDIATE || type == CertificateType.ROOT) {
            keyUsageFlags |= KeyUsage.keyCertSign;
            keyUsageFlags |= KeyUsage.cRLSign;
        }

        if (extensions != null) {
            for (String ext : extensions) {
                switch (ext) {
                    // Key Usage
                    case "digitalSignature": keyUsageFlags |= KeyUsage.digitalSignature; break;
                    case "nonRepudiation": keyUsageFlags |= KeyUsage.nonRepudiation; break;
                    case "keyEncipherment": keyUsageFlags |= KeyUsage.keyEncipherment; break;
                    case "dataEncipherment": keyUsageFlags |= KeyUsage.dataEncipherment; break;
                    // Extended Key Usage
                    case "serverAuth": ekuList.add(KeyPurposeId.id_kp_serverAuth); break;
                    case "clientAuth": ekuList.add(KeyPurposeId.id_kp_clientAuth); break;
                    case "codeSigning": ekuList.add(KeyPurposeId.id_kp_codeSigning); break;
                    case "emailProtection": ekuList.add(KeyPurposeId.id_kp_emailProtection); break;
                }
            }
        }

        if (keyUsageFlags > 0) {
            certBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(keyUsageFlags));
        }
        if (!ekuList.isEmpty()) {
            certBuilder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(ekuList.toArray(new KeyPurposeId[0])));
        }

        // 3. Subject Alternative Name (SAN)
        if (subjectAlternativeNames != null && !subjectAlternativeNames.isEmpty()) {
            List<GeneralName> generalNames = new ArrayList<>();
            for (SanDto san : subjectAlternativeNames) {
                int tagNo;
                switch (san.getType().toUpperCase()) {
                    case "DNS": tagNo = GeneralName.dNSName; break;
                    case "IP": tagNo = GeneralName.iPAddress; break;
                    case "EMAIL": tagNo = GeneralName.rfc822Name; break;
                    case "URI": tagNo = GeneralName.uniformResourceIdentifier; break;
                    default: continue; // Preskoči nepoznate tipove
                }
                generalNames.add(new GeneralName(tagNo, san.getValue()));
            }
            if (!generalNames.isEmpty()) {
                certBuilder.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(generalNames.toArray(new GeneralName[0])));
            }
        }

        // 4. CRL Distribution Point (CDP)
        String crlUrl = cfg.getCrlBaseUrl() + "/" + issuer.getSerialNumber().toString() + ".crl";
        GeneralName gn = new GeneralName(GeneralName.uniformResourceIdentifier, crlUrl);
        DistributionPointName distPointName = new DistributionPointName(new GeneralNames(gn));
        DistributionPoint distPoint = new DistributionPoint(distPointName, null, null);
        CRLDistPoint crlDistPoint = new CRLDistPoint(new DistributionPoint[] { distPoint });
        certBuilder.addExtension(Extension.cRLDistributionPoints, false, crlDistPoint);

        // Potpisivanje i generisanje sertifikata
        return new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(certBuilder.build(signer));
    }
}