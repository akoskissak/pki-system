package com.ftn.bsep.pki.service;

import com.ftn.bsep.pki.dto.IntermediateRequest;
import com.ftn.bsep.pki.dto.SelfSignedRequest;
import com.ftn.bsep.pki.dto.SelfSignedResponse;
import com.ftn.bsep.pki.entity.*;
import com.ftn.bsep.pki.entity.Certificate;
import com.ftn.bsep.pki.repository.ICertificateRepository;
import com.ftn.bsep.pki.repository.IUserRepository;
import org.apache.commons.lang3.RandomStringUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.springframework.stereotype.Service;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import static com.ftn.bsep.pki.entity.RoleName.CA_USER;

@Service
public class CertificateService {
    private final KeyStoreService keyStoreService;
    private final IUserRepository userRepository;
    private final EncryptionService encryptionService;
    private final ICertificateRepository certificateRepository;

    public CertificateService(KeyStoreService keyStoreService, ICertificateRepository certificateRepository, IUserRepository userRepository, EncryptionService encryptionService) {
        this.keyStoreService = keyStoreService;
        this.userRepository = userRepository;
        this.encryptionService = encryptionService;
        this.certificateRepository = certificateRepository;
    }

    public SelfSignedResponse createSelfSigned(SelfSignedRequest req) throws Exception {
        User owner = userRepository.findById(req.ownerId())
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (owner.getSymmetricKey() == null || owner.getSymmetricKey().isEmpty()) {
            throw new IllegalStateException("User does not have a symmetric key for encryption.");
        }

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        X500NameBuilder subjectBuilder = new X500NameBuilder(BCStyle.INSTANCE);
        subjectBuilder.addRDN(BCStyle.CN, req.commonName());
        subjectBuilder.addRDN(BCStyle.SURNAME, req.surname());
        subjectBuilder.addRDN(BCStyle.GIVENNAME, req.givenname());
        subjectBuilder.addRDN(BCStyle.O, req.organization());
        subjectBuilder.addRDN(BCStyle.OU, req.organizationalUnit());
        subjectBuilder.addRDN(BCStyle.C, req.country());

        Instant now = Instant.now();
        Subject subject = new Subject();
        subject.setPublicKey(kp.getPublic());
        subject.setX500Name(subjectBuilder.build());
        subject.setSerialNumber(new BigInteger(64, new SecureRandom()));
        subject.setStartDate(Date.from(now));
        subject.setEndDate(Date.from(now.plus(req.validityDays(), ChronoUnit.DAYS)));

        Issuer issuer = new Issuer();
        issuer.setPrivateKey(kp.getPrivate());
        issuer.setX500Name(subjectBuilder.build());

        X509Certificate cert = keyStoreService.generateCertificate(subject, issuer, CertificateType.ROOT, req.extensions());

        X509Certificate[] chain = { cert };

        String keyStorePassword = RandomStringUtils.randomAlphanumeric(16);
        System.out.println("Keystore lozinka za testiranje je: " + keyStorePassword);

        Path p12 = keyStoreService.saveCertificateChain(
                chain,
                kp.getPrivate(),
                cert.getSerialNumber().toString(),
                keyStorePassword.toCharArray()
        );

        String encryptedPassword = encryptionService.encrypt(keyStorePassword, owner.getSymmetricKey());

        Certificate certificateEntity = new Certificate();

        certificateEntity.setSerialNumber(cert.getSerialNumber().toString());
        certificateEntity.setSubjectCommonName(req.commonName());
        certificateEntity.setSubjectSurname(req.surname());
        certificateEntity.setSubjectGivenname(req.givenname());
        certificateEntity.setSubjectOrganization(req.organization());
        certificateEntity.setSubjectOrganizationalUnit(req.organizationalUnit());
        certificateEntity.setSubjectCountry(req.country());
        certificateEntity.setIssuerCommonName(req.commonName());
        certificateEntity.setIssuerOrganization(req.organization());
        certificateEntity.setNotBefore(cert.getNotBefore().toInstant());
        certificateEntity.setNotAfter(cert.getNotAfter().toInstant());
        certificateEntity.setType(CertificateType.ROOT);
        certificateEntity.setParentCertificate(null);
        certificateEntity.setRevoked(false);
        certificateEntity.setKeyStorePath(p12.toString());
        certificateEntity.setKeyStorePassword(encryptedPassword);
        certificateEntity.setOwner(owner);

        certificateRepository.save(certificateEntity);

        return new SelfSignedResponse("CN=" + req.commonName(), p12.toString());
    }

    public Certificate issueIntermediate(IntermediateRequest req) throws Exception {
        System.out.println("➡️ Starting issueIntermediate for: " + req.commonName());

        // --- Učitavanje issuer sertifikata ---
        Certificate issuerCertEntity = certificateRepository.findById(req.issuerId())
                .orElseThrow(() -> new RuntimeException("Issuer certificate not found"));
        System.out.println("Issuer cert entity: " + issuerCertEntity.getSerialNumber());

        if (issuerCertEntity.isRevoked()) {
            throw new Exception("Issuer certificate is revoked");
        }

        Instant now = Instant.now();
        System.out.println("Now: " + now);
        System.out.println("Issuer validity: " + issuerCertEntity.getNotBefore() + " - " + issuerCertEntity.getNotAfter());

        if (now.isBefore(issuerCertEntity.getNotBefore()) || now.isAfter(issuerCertEntity.getNotAfter())) {
            throw new Exception("Issuer certificate is not valid currently.");
        }

        User issuerOwner = userRepository.findById(req.issuerOwnerId())
                .orElseThrow(() -> new RuntimeException("Issuer owner not found"));
        System.out.println("Issuer owner: " + issuerOwner.getEmail());

        String plainPassword = encryptionService.decrypt(
                issuerCertEntity.getKeyStorePassword(),
                issuerOwner.getSymmetricKey()
        );
        System.out.println("Decrypted keystore password length: " + plainPassword.length());

        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (var fis = new java.io.FileInputStream(issuerCertEntity.getKeyStorePath())) {
            ks.load(fis, plainPassword.toCharArray());
        }
        System.out.println("Loaded keystore from: " + issuerCertEntity.getKeyStorePath());

        // --- Preuzimanje sertifikata izdavaoca ---
        String issuerAlias = issuerCertEntity.getSerialNumber();
        System.out.println("Using alias: " + issuerAlias);

        X509Certificate issuerCert = (X509Certificate) ks.getCertificate(issuerAlias);
        if (issuerCert == null) {
            throw new RuntimeException("Issuer certificate not found in keystore.");
        }
        System.out.println("Issuer cert subject: " + issuerCert.getSubjectX500Principal());
        System.out.println("Issuer cert issuer : " + issuerCert.getIssuerX500Principal());

        java.security.cert.Certificate[] issuerChain = ks.getCertificateChain(issuerAlias);
        if (issuerChain == null || issuerChain.length == 0) {
            System.out.println("Issuer chain is empty, using single cert");
            issuerChain = new java.security.cert.Certificate[]{issuerCert};
        }
        System.out.println("Issuer chain length: " + issuerChain.length);

        // --- Validacija chain-a ---
        try {
            validateCertificateChain(issuerChain);
            System.out.println("Issuer chain validated OK");
        } catch (Exception e) {
            System.out.println("❌ validateCertificateChain failed: " + e.getMessage());
            throw e;
        }

        PrivateKey issuerPrivateKey = (PrivateKey) ks.getKey(issuerAlias, plainPassword.toCharArray());
        System.out.println("Loaded issuer private key: " + (issuerPrivateKey != null));

        // --- Kreiranje novog sertifikata ---
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair subjectKeyPair = kpg.generateKeyPair();
        System.out.println("Generated subject keypair");

        X500NameBuilder subjectBuilder = new X500NameBuilder(BCStyle.INSTANCE);
        subjectBuilder.addRDN(BCStyle.CN, req.commonName());
        subjectBuilder.addRDN(BCStyle.O, req.organization());
        subjectBuilder.addRDN(BCStyle.OU, req.organizationalUnit());
        subjectBuilder.addRDN(BCStyle.C, req.country());

        Subject subject = new Subject();
        subject.setPublicKey(subjectKeyPair.getPublic());
        subject.setX500Name(subjectBuilder.build());
        subject.setSerialNumber(new BigInteger(64, new SecureRandom()));
        subject.setStartDate(Date.from(now));
        subject.setEndDate(Date.from(now.plus(req.validityDays(), ChronoUnit.DAYS)));

        Issuer issuer = new Issuer();
        issuer.setPrivateKey(issuerPrivateKey);

        X500Principal issuerPrincipal = issuerCert.getSubjectX500Principal();
        issuer.setX500Name(X500Name.getInstance(issuerPrincipal.getEncoded()));
        System.out.println("Issuer X500Name: " + issuer.getX500Name());

        X509Certificate newCert = keyStoreService.generateCertificate(
                subject, issuer, CertificateType.INTERMEDIATE, req.extensions()
        );
        System.out.println("Generated new intermediate cert");
        System.out.println("New cert subject: " + newCert.getSubjectX500Principal());
        System.out.println("New cert issuer : " + newCert.getIssuerX500Principal());

        // --- Pravi fullChain: novi certifikat + chain izdavaoca ---
        X509Certificate[] fullChain = new X509Certificate[1 + issuerChain.length];
        fullChain[0] = newCert;
        for (int i = 0; i < issuerChain.length; i++) {
            fullChain[i + 1] = (X509Certificate) issuerChain[i];
        }
        System.out.println("Full chain length: " + fullChain.length);

        // --- Verifikacija digitalnog potpisa novog sertifikata ---
        try {
            newCert.verify(issuerCert.getPublicKey());
            System.out.println("✅ Digital signature check PASSED");
        } catch (Exception e) {
            System.out.println("❌ Digital signature check FAILED: " + e.getMessage());
            throw new RuntimeException("Digital signature of new certificate is invalid: " + e.getMessage());
        }

        String keyStorePassword = RandomStringUtils.randomAlphanumeric(16);
        Path p12 = keyStoreService.saveCertificateChain(
                fullChain,
                subjectKeyPair.getPrivate(),
                newCert.getSerialNumber().toString(),
                keyStorePassword.toCharArray()
        );
        System.out.println("Saved new keystore: " + p12);

        String encryptedPassword = encryptionService.encrypt(keyStorePassword, issuerOwner.getSymmetricKey());

        Certificate entity = new Certificate();
        entity.setSerialNumber(newCert.getSerialNumber().toString());
        entity.setSubjectCommonName(req.commonName());
        entity.setSubjectOrganization(req.organization());
        entity.setSubjectGivenname(null);
        entity.setSubjectSurname(null);
        entity.setSubjectOrganizationalUnit(req.organizationalUnit());
        entity.setSubjectCountry(req.country());
        entity.setIssuerCommonName(issuerCertEntity.getSubjectCommonName());
        entity.setIssuerOrganization(issuerCertEntity.getSubjectOrganization());
        entity.setNotBefore(newCert.getNotBefore().toInstant());
        entity.setNotAfter(newCert.getNotAfter().toInstant());
        entity.setType(CertificateType.INTERMEDIATE);
        entity.setParentCertificate(issuerCertEntity);
        entity.setRevoked(false);
        entity.setKeyStorePath(p12.toString());
        entity.setKeyStorePassword(encryptedPassword);
        entity.setOwner(issuerOwner);

        if("CA_USER".equals(issuerOwner.getRole().getName().toString())) {
            if (!req.organization().equals(issuerOwner.getOrganization())) {
                throw new RuntimeException("CA user cannot issue certificate for another organization");
            }
        }

        // --- Ograničenje trajanja sertifikata ---
        Instant requestedNotAfter = now.plus(req.validityDays(), ChronoUnit.DAYS);
        if (requestedNotAfter.isAfter(issuerCertEntity.getNotAfter())) {
            throw new RuntimeException("Cannot issue certificate that expires after the issuer certificate");
        }



        System.out.println("✅ Intermediate certificate created successfully: " + entity.getSerialNumber());

        return certificateRepository.save(entity);
    }



    private void validateCertificateChain(java.security.cert.Certificate[] chain) throws Exception {
        if (chain == null || chain.length == 0) {
            throw new Exception("Certificate chain is empty or null.");
        }

        for (java.security.cert.Certificate cert : chain) {
            try {
                ((X509Certificate) cert).checkValidity();
            } catch (CertificateExpiredException | CertificateNotYetValidException e) {
                throw new Exception("Certificate in the chain is not valid: " + ((X509Certificate) cert).getSubjectX500Principal().getName() + ". Razlog: " + e.getMessage());
            }
        }

        for (int i = 0; i < chain.length - 1; ++i) {
            X509Certificate currentCert = (X509Certificate) chain[i];
            X509Certificate issuerCert = (X509Certificate) chain[i + 1];

            try {
                currentCert.verify(issuerCert.getPublicKey());
            } catch (Exception e) {
                throw new Exception("Digital signature of the certificate in the chain is invalid: " + currentCert.getSubjectX500Principal().getName() + ". Razlog: " + e.getMessage());
            }
        }
    }

    public List<Certificate> getCertificatesForUser(User user) {
        String role = String.valueOf(user.getRole().getName());

        if ("ADMIN".equals(role)) {
            return certificateRepository.findAll();
        } else if ("CA_USER".equals(role)) {
            return certificateRepository.findAllByOrganization(user.getOrganization());
        }

        return new ArrayList<>();
    }
}