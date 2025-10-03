package com.ftn.bsep.pki.service;

import com.ftn.bsep.pki.controller.RevocationController;
import com.ftn.bsep.pki.entity.Certificate;
import com.ftn.bsep.pki.repository.ICertificateRepository;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.X509CRLHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.FileOutputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class RevocationService {
    private final ICertificateRepository certificateRepository;
    private final EncryptionService encryptionService;

    private final Path crlFolder = Path.of("crl");
    private static final Logger logger = LoggerFactory.getLogger(RevocationController.class);

    public RevocationService(ICertificateRepository certificateRepository, EncryptionService encryptionService) {
        this.certificateRepository = certificateRepository;
        this.encryptionService = encryptionService;
    }

    public void revokeCertificate(Long certId, int reason, Instant revokedAt, Long revokerUserId) throws Exception {
        logger.info("Starting revocation process for certId={} by userId={} at {}", certId, revokerUserId, revokedAt);

        Certificate certToRevoke  = certificateRepository.findById(certId)
                .orElseThrow(() -> {
                    logger.error("Certificate with id={} not found. Revocation aborted.", certId);
                    return new IllegalArgumentException("Certificate not found");
                });

        if (certToRevoke.isRevoked()) {
            logger.warn("Certificate id={} (serialNumber={}) is already revoked. Skipping revocation.",
                    certToRevoke.getId(), certToRevoke.getSerialNumber());
            return;
        }
        logger.debug("Revoking certificate: id={}, serialNumber={}, reason={}, revokedAt={}",
                certToRevoke.getId(), certToRevoke.getSerialNumber(), reason, revokedAt);

        recursiveRevoke(certToRevoke, reason, revokedAt);

        Certificate issuer = certToRevoke.getParentCertificate();
        if (issuer == null) {
            logger.info("Certificate id={} is a ROOT certificate. Using self as issuer.", certToRevoke.getId());
            issuer = certToRevoke;
        }
        
        logger.info("Generating CRL for issuer certId={} (serialNumber={})", issuer.getId(), issuer.getSerialNumber());
        generateCrlForIssuer(issuer.getId());

        logger.info("Successfully revoked certId={} (serialNumber={}) and updated CRL for issuer={}",
                certToRevoke.getId(), certToRevoke.getSerialNumber(), issuer.getSerialNumber());

    }


    private void recursiveRevoke(Certificate cert, int reason, Instant revokedAt) {
        if (cert.isRevoked()) {
            return;
        }

        cert.setRevoked(true);
        cert.setRevokedAt(revokedAt);
        cert.setRevocationReason(reason);
        certificateRepository.save(cert);

        System.out.println("✅ Povucen sertifikat sa ID-jem: " + cert.getId() + " i serijskim brojem: " + cert.getSerialNumber());

        List<Certificate> children = certificateRepository.findByParentCertificate(cert);

        if (children != null && !children.isEmpty()) {
            System.out.println("Pronadjeni podređeni sertifikati. Pokreće se rekurzivno povlačenje...");
            for (Certificate child : children) {
                recursiveRevoke(child, reason, revokedAt);
            }
        }
    }

    public Path generateCrlForIssuer(Long issuerId) throws Exception {
        Certificate issuerEntity = certificateRepository.findById(issuerId)
                .orElseThrow(() -> new IllegalArgumentException("Issuer not found"));

        //String plainPassword = encryptionService.decrypt(issuerEntity.getKeyStorePassword(), issuerEntity.getOwner().getSymmetricKey());
        String encryptedUserKey = issuerEntity.getOwner().getSymmetricKey();
        if (encryptedUserKey == null || encryptedUserKey.isEmpty()) {
            throw new IllegalStateException("Vlasnik sertifikata izdavaoca nema simetrični ključ.");
        }

        String plainUserKey = encryptionService.decryptUserKey(encryptedUserKey);

        String plainPassword = encryptionService.decrypt(issuerEntity.getKeyStorePassword(), plainUserKey);
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (var fis = new java.io.FileInputStream(issuerEntity.getKeyStorePath())) {
            ks.load(fis, plainPassword.toCharArray());
        }

        String issuerAlias = issuerEntity.getSerialNumber();
        X509Certificate issuerCert = (X509Certificate) ks.getCertificate(issuerAlias);
        PrivateKey issuerPrivateKey = (PrivateKey) ks.getKey(issuerAlias, plainPassword.toCharArray());

        List<Certificate> revoked = certificateRepository.findAll().stream()
                .filter(c -> c.isRevoked())
                .filter(c -> {
                    Certificate p = c.getParentCertificate();
                    return p != null && p.getId().equals(issuerId);
                })
                .collect(Collectors.toList());

        Instant now = Instant.now();

        X500Name issuerName = X500Name.getInstance(issuerCert.getSubjectX500Principal().getEncoded());
        X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(issuerName, Date.from(now));

        for (Certificate rc : revoked) {
            BigInteger serial = new BigInteger(rc.getSerialNumber()); // ako je serialNumber string broja
            Date revocationDate = Date.from(rc.getRevokedAt() != null ? rc.getRevokedAt() : now);
            int reasonCode = rc.getRevocationReason() != null ? rc.getRevocationReason() : 0;

            org.bouncycastle.asn1.x509.CRLReason cr = org.bouncycastle.asn1.x509.CRLReason.lookup(reasonCode);
            org.bouncycastle.asn1.ASN1EncodableVector reasonVec = new org.bouncycastle.asn1.ASN1EncodableVector();
            crlBuilder.addCRLEntry(serial, revocationDate, new Extensions(
                            new Extension(
                                    Extension.reasonCode,
                                    false,
                                    new DEROctetString(cr.toASN1Primitive().getEncoded())
                            )
                    )
            );
        }

        // signature
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(issuerPrivateKey);

        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        crlBuilder.addExtension(org.bouncycastle.asn1.x509.Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(issuerCert));
        crlBuilder.addExtension(org.bouncycastle.asn1.x509.Extension.issuerAlternativeName, false, issuerName);

        X509CRLHolder crlHolder = crlBuilder.build(signer);
        JcaX509CRLConverter converter = new JcaX509CRLConverter().setProvider("BC");
        X509CRL crl = converter.getCRL(crlHolder);

        // snimi CRL na disk
        if (!java.nio.file.Files.exists(crlFolder)) {
            java.nio.file.Files.createDirectories(crlFolder);
        }
        Path crlFile = crlFolder.resolve(issuerEntity.getSerialNumber() + ".crl");
        try (OutputStream os = new FileOutputStream(crlFile.toFile())) {
            os.write(crl.getEncoded());
        }

        issuerEntity.setCrlPath(crlFile.toString());
        certificateRepository.save(issuerEntity);

        return crlFile;
    }

    public boolean isRevokedInCrl(X509Certificate cert, Path crlFile) throws Exception {
        if (crlFile == null || !java.nio.file.Files.exists(crlFile)) return false;
        try (var in = new java.io.FileInputStream(crlFile.toFile())) {
            java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory.getInstance("X.509");
            java.security.cert.CRL crl = cf.generateCRL(in);
            if (crl instanceof java.security.cert.X509CRL) {
                return ((java.security.cert.X509CRL) crl).isRevoked(cert);
            }
            return false;
        }
    }
}

