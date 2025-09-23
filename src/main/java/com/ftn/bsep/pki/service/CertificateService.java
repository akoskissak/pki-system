package com.ftn.bsep.pki.service;

import com.ftn.bsep.pki.dto.*;
import com.ftn.bsep.pki.entity.*;
import com.ftn.bsep.pki.entity.Certificate;
import com.ftn.bsep.pki.repository.ICertificateRepository;
import com.ftn.bsep.pki.repository.IPendingCsrRepository;
import com.ftn.bsep.pki.repository.IUserRepository;
import org.apache.commons.lang3.RandomStringUtils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import javax.security.auth.x500.X500Principal;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.math.BigInteger;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import java.util.*;
import java.util.stream.Collectors;

import static com.ftn.bsep.pki.entity.CertificateType.INTERMEDIATE;


@Service
public class CertificateService {
    private final KeyStoreService keyStoreService;
    private final IUserRepository userRepository;
    private final EncryptionService encryptionService;
    private final ICertificateRepository certificateRepository;
    private final IPendingCsrRepository pendingCsrRepository;

    public CertificateService(KeyStoreService keyStoreService, ICertificateRepository certificateRepository, IUserRepository userRepository, EncryptionService encryptionService, IPendingCsrRepository pendingCsrRepository) {
        this.keyStoreService = keyStoreService;
        this.userRepository = userRepository;
        this.encryptionService = encryptionService;
        this.certificateRepository = certificateRepository;
        this.pendingCsrRepository = pendingCsrRepository;
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
        BigInteger serialNumber = new BigInteger(64, new SecureRandom());

        Subject subject = new Subject();
        subject.setPublicKey(kp.getPublic());
        subject.setX500Name(subjectBuilder.build());
        subject.setSerialNumber(serialNumber);
        subject.setStartDate(Date.from(now));
        subject.setEndDate(Date.from(now.plus(req.validityDays(), ChronoUnit.DAYS)));

        Issuer issuer = new Issuer();
        issuer.setPrivateKey(kp.getPrivate());
        issuer.setX500Name(subjectBuilder.build());
        issuer.setSerialNumber(serialNumber);

        X509Certificate cert = keyStoreService.generateCertificate(subject, issuer, CertificateType.ROOT, req.extensions(), req.subjectAlternativeNames());

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

        boolean isEncryptionCertificate = false;
        if (req.extensions() != null) {
            for (String ext : req.extensions()) {
                if(ext.equals("keyEncipherment")) {
                    isEncryptionCertificate = true;
                    break;
                }
            }
        }

        Certificate certificateEntity = new Certificate();
        certificateEntity.setEncryptionCertificate(isEncryptionCertificate);
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
        if (issuerCert.getBasicConstraints() == -1) {
            throw new Exception("Sertifikat izdavaoca (" + issuerCert.getSubjectX500Principal().getName() + ") nije CA i ne može da izdaje druge sertifikate.");
        }

        boolean[] keyUsage = issuerCert.getKeyUsage();
        // Prema X.509 standardu, 'keyCertSign' je na indeksu 5.
        if (keyUsage != null && !keyUsage[5]) {
            throw new Exception("Sertifikat izdavaoca nema 'keyCertSign' dozvolu i ne može da potpisuje druge sertifikate.");
        }
        System.out.println("✅ Provere CA i KeyUsage dozvola izdavaoca su uspešne.");
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

        BigInteger serialNumber = new BigInteger(64, new SecureRandom());

        Subject subject = new Subject();
        subject.setPublicKey(subjectKeyPair.getPublic());
        subject.setX500Name(subjectBuilder.build());
        subject.setSerialNumber(serialNumber);
        subject.setStartDate(Date.from(now));
        subject.setEndDate(Date.from(now.plus(req.validityDays(), ChronoUnit.DAYS)));

        Issuer issuer = new Issuer();
        issuer.setPrivateKey(issuerPrivateKey);
        issuer.setSerialNumber(serialNumber);
        X500Principal issuerPrincipal = issuerCert.getSubjectX500Principal();
        issuer.setX500Name(X500Name.getInstance(issuerPrincipal.getEncoded()));
        System.out.println("Issuer X500Name: " + issuer.getX500Name());

        X509Certificate newCert = keyStoreService.generateCertificate(
                subject, issuer, INTERMEDIATE, req.extensions(), req.subjectAlternativeNames()
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
        entity.setType(INTERMEDIATE);
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

    public Certificate issueEndEntity(EndEntityRequest req, Long ownerId, boolean isEncryptionCertificate) throws Exception {
        System.out.println("➡️ Starting issueEndEntity for: " + req.commonName());

        Certificate issuerCertEntity = certificateRepository.findById(req.issuerId())
                .orElseThrow(() -> new RuntimeException("Issuer certificate not found"));

        if (issuerCertEntity.isRevoked()) {
            throw new Exception("Issuer certificate is revoked");
        }

        Instant now = Instant.now();
        Instant requestedEndDate = now.plus(req.validityDays(), ChronoUnit.DAYS);
        Instant issuerEndDate = issuerCertEntity.getNotAfter();

        if (requestedEndDate.isAfter(issuerEndDate)) {
            throw new IllegalArgumentException(
                    "Certificate validity cannot extend beyond the issuer's validity period. Issuer expires on: " + issuerEndDate
            );
        }

        User issuerOwner = userRepository.findById(req.issuerOwnerId())
                .orElseThrow(() -> new RuntimeException("Issuer owner not found"));

        User owner = userRepository.findById(ownerId)
                .orElseThrow(() -> new RuntimeException("Owner not found"));

        String plainPassword = encryptionService.decrypt(
                issuerCertEntity.getKeyStorePassword(),
                issuerOwner.getSymmetricKey()
        );

        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (var fis = new java.io.FileInputStream(issuerCertEntity.getKeyStorePath())) {
            ks.load(fis, plainPassword.toCharArray());
        }

        String issuerAlias = issuerCertEntity.getSerialNumber();
        X509Certificate issuerCert = (X509Certificate) ks.getCertificate(issuerAlias);
        PrivateKey issuerPrivateKey = (PrivateKey) ks.getKey(issuerAlias, plainPassword.toCharArray());

        byte[] publicKeyBytes = Base64.getDecoder().decode(req.publicKey());
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey subjectPublicKey = kf.generatePublic(new X509EncodedKeySpec(publicKeyBytes));

        X500NameBuilder subjectBuilder = new X500NameBuilder(BCStyle.INSTANCE);
        subjectBuilder.addRDN(BCStyle.CN, req.commonName());
        subjectBuilder.addRDN(BCStyle.SURNAME, req.surname());
        subjectBuilder.addRDN(BCStyle.GIVENNAME, req.givenname());
        subjectBuilder.addRDN(BCStyle.O, req.organization());
        subjectBuilder.addRDN(BCStyle.OU, req.organizationalUnit());
        subjectBuilder.addRDN(BCStyle.C, req.country());

        BigInteger serialNumber = new BigInteger(64, new SecureRandom());

        Subject subject = new Subject();
        subject.setPublicKey(subjectPublicKey);
        subject.setX500Name(subjectBuilder.build());
        subject.setSerialNumber(serialNumber);
        subject.setStartDate(Date.from(now));
        subject.setEndDate(Date.from(now.plus(req.validityDays(), ChronoUnit.DAYS)));

        Issuer issuer = new Issuer();
        issuer.setPrivateKey(issuerPrivateKey);
        issuer.setSerialNumber(serialNumber);
        issuer.setX500Name(X500Name.getInstance(issuerCert.getSubjectX500Principal().getEncoded()));

        X509Certificate newCert = keyStoreService.generateEECertificate(
                subject, issuer, CertificateType.END_ENTITY, req.extensions()
        );

        Path certPath = keyStoreService.saveEECertificate(newCert);
        System.out.println("Saved EE certificate to: " + certPath);

        Certificate entity = new Certificate();
        entity.setEncryptionCertificate(isEncryptionCertificate);
        entity.setSerialNumber(newCert.getSerialNumber().toString());
        entity.setSubjectCommonName(req.commonName());
        entity.setSubjectSurname(req.surname());
        entity.setSubjectGivenname(req.givenname());
        entity.setSubjectOrganization(req.organization());
        entity.setSubjectOrganizationalUnit(req.organizationalUnit());
        entity.setSubjectCountry(req.country());
        entity.setIssuerCommonName(issuerCertEntity.getSubjectCommonName());
        entity.setIssuerOrganization(issuerCertEntity.getSubjectOrganization());
        entity.setNotBefore(newCert.getNotBefore().toInstant());
        entity.setNotAfter(newCert.getNotAfter().toInstant());
        entity.setType(CertificateType.END_ENTITY);
        entity.setParentCertificate(issuerCertEntity);
        entity.setRevoked(false);
        entity.setKeyStorePath(certPath.toString());
        String randomPassword = new BigInteger(130, new SecureRandom()).toString(32);
        entity.setKeyStorePassword(randomPassword);
        entity.setOwner(owner);
        return certificateRepository.save(entity);
    }

    public Certificate issueFromPendingCsr(Long requestId) throws Exception {
        PendingCsrRequest pendingRequest = pendingCsrRepository.findById(requestId)
                .orElseThrow(() -> new IllegalArgumentException("Pending CSR request with id " + requestId + " not found."));

        PKCS10CertificationRequest csr;
        try (PEMParser pemParser = new PEMParser(new StringReader(pendingRequest.getCsrContent()))) {
            Object parsedObject = pemParser.readObject();
            if (!(parsedObject instanceof PKCS10CertificationRequest)) {
                throw new IllegalArgumentException("Invalid CSR content in database for request " + requestId);
            }
            csr = (PKCS10CertificationRequest) parsedObject;
        }

        JcaPKCS10CertificationRequest jcaCSR = new JcaPKCS10CertificationRequest(csr);
        PublicKey publicKey = jcaCSR.getPublicKey();
        X500Name subjectName = jcaCSR.getSubject();

        String commonName = getRdnString(subjectName, BCStyle.CN);
        String surname = getRdnString(subjectName, BCStyle.SURNAME);
        String givenname = getRdnString(subjectName, BCStyle.GIVENNAME);
        String organization = getRdnString(subjectName, BCStyle.O);
        String organizationalUnit = getRdnString(subjectName, BCStyle.OU);
        String country = getRdnString(subjectName, BCStyle.C);

        if (!jcaCSR.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(publicKey))) {
            throw new RuntimeException("CSR signature is invalid.");
        }

        Extensions extensions = csr.getRequestedExtensions();
        boolean isEncryptionCertificate = false;
        List<String> extList = new ArrayList<>();
        if (extensions != null) {
            Extension keyUsageExt = extensions.getExtension(Extension.keyUsage);
            if (keyUsageExt != null) {
                KeyUsage ku = KeyUsage.getInstance(keyUsageExt.getParsedValue());
                if (ku.hasUsages(KeyUsage.digitalSignature)) extList.add("digitalSignature");
                if (ku.hasUsages(KeyUsage.nonRepudiation)) extList.add("nonRepudiation");
                if (ku.hasUsages(KeyUsage.keyEncipherment)) {
                    extList.add("keyEncipherment");
                    isEncryptionCertificate = true;
                }
                if (ku.hasUsages(KeyUsage.dataEncipherment)) extList.add("dataEncipherment");
            }
        }

        Certificate caCert = certificateRepository.findBySerialNumber(pendingRequest.getIssuerId());
        if (caCert == null) {
            throw new IllegalArgumentException("Issuer CA not found.");
        }

        EndEntityRequest req = new EndEntityRequest(
                caCert.getId(),
                caCert.getOwner().getId(), //DISKUTABILNO!!!
                Base64.getEncoder().encodeToString(publicKey.getEncoded()),
                commonName,
                surname,
                givenname,
                organization,
                organizationalUnit,
                country,
                pendingRequest.getValidityDays(),
                extList
        );

        Long ownerId =  pendingRequest.getOwnerId();
        pendingCsrRepository.deleteById(requestId);
        return this.issueEndEntity(req, ownerId, isEncryptionCertificate);
    }

    private String getRdnString(X500Name subjectName, ASN1ObjectIdentifier rdnType) {
        RDN[] rdns = subjectName.getRDNs(rdnType);
        if (rdns.length > 0) {
            return IETFUtils.valueToString(rdns[0].getFirst().getValue());
        }
        return "";
    }



   /* private void validateCertificateChain(java.security.cert.Certificate[] chain) throws Exception {
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

            com.ftn.bsep.pki.entity.Certificate issuerEntity = certificateRepository.findBySerialNumber(issuerCert.getSerialNumber().toString());
            if (issuerEntity != null && issuerEntity.getCrlPath() != null && !issuerEntity.getCrlPath().isEmpty()) {
                Path crlPath = Path.of(issuerEntity.getCrlPath());
                RevocationService revocationService = new RevocationService(certificateRepository, encryptionService);// injektuj RevocationService u klasu i koristi ga
                boolean revoked = revocationService.isRevokedInCrl(currentCert, crlPath);
                if (revoked) {
                    throw new Exception("Certificate " + currentCert.getSubjectX500Principal().getName() + " is revoked according to CRL of issuer " + issuerCert.getSubjectX500Principal().getName());
                }
            }

            // proveri potpis kao i do sada
            try {
                currentCert.verify(issuerCert.getPublicKey());
            } catch (Exception e) {
                throw new Exception("Digital signature of the certificate in the chain is invalid: " + currentCert.getSubjectX500Principal().getName() + ". Razlog: " + e.getMessage());
            }
        }
    }*/

    private void validateCertificateChain(java.security.cert.Certificate[] chain) throws Exception {
        if (chain == null || chain.length == 0) {
            throw new Exception("Lanac sertifikata je prazan.");
        }

        for (int i = 0; i < chain.length; i++) {
            X509Certificate currentCert = (X509Certificate) chain[i];
            String serialNumber = currentCert.getSerialNumber().toString();
            String subjectName = currentCert.getSubjectX500Principal().getName();

            // Provјera 1: Period važenja
            try {
                currentCert.checkValidity();
            } catch (CertificateExpiredException | CertificateNotYetValidException e) {
                throw new Exception("Sertifikat u lancu nije validan: " + subjectName + ". Razlog: " + e.getMessage());
            }

            // Provјera 2: Status povučenosti
            Certificate certEntity = certificateRepository.findBySerialNumber(serialNumber);
            if (certEntity == null) {
                throw new Exception("Sertifikat " + subjectName + " nije pronađen u sistemu.");
            }
            if (certEntity.isRevoked()) {
                throw new Exception("Sertifikat u lancu je povučen (revoked): " + subjectName);
            }

            // Provјera 3: Digitalni potpis
            if (i < chain.length - 1) {
                X509Certificate issuerCert = (X509Certificate) chain[i + 1];
                try {
                    currentCert.verify(issuerCert.getPublicKey());
                } catch (Exception e) {
                    throw new Exception("Digitalni potpis za sertifikat " + subjectName + " nije ispravan.");
                }
            } else {
                try {
                    currentCert.verify(currentCert.getPublicKey());
                } catch (Exception e) {
                    throw new Exception("Root sertifikat " + subjectName + " nije ispravno samopotpisan.");
                }
            }
        }
        System.out.println("✅ Validacija lanca sertifikata uspešno završena.");
    }


    public List<Certificate> getCertificatesForUser(User user) {
        String role = String.valueOf(user.getRole().getName());

        if ("ADMIN".equals(role)) {
            return certificateRepository.findAll();
        } else if ("CA_USER".equals(role)) {
            return certificateRepository.findAllByOrganization(user.getOrganization());
        } else if ("END_USER".equals(role)) {
            return certificateRepository.findByOwnerId(user.getId());
        }

        return new ArrayList<>();
    }

    public void handlePendingCsr(MultipartFile csrFile, String issuerId, Integer validityDays, Long ownerId) throws Exception {
        Certificate caCert = certificateRepository.findBySerialNumber(issuerId);
        if (caCert == null) {
            throw new IllegalArgumentException("Issuer CA not found.");
        }

        long caRemainingDays = Duration.between(Instant.now(), caCert.getNotAfter()).toDays();
        if (validityDays > caRemainingDays) {
            throw new IllegalArgumentException("Requested validity exceeds the remaining validity of the issuer CA.");
        }
        try {
            String csrContent = new String(csrFile.getBytes());

            PKCS10CertificationRequest csr;
            try (PEMParser pemParser = new PEMParser(new StringReader(csrContent))) {
                Object parsedObject = pemParser.readObject();

                if (parsedObject instanceof PKCS10CertificationRequest) {
                    csr = (PKCS10CertificationRequest) parsedObject;
                } else {
                    throw new IllegalArgumentException("Invalid CSR file. Could not parse PEM content.");
                }
            }

            X500Name subjectName = new JcaPKCS10CertificationRequest(csr).getSubject();
            String commonName = getRdnString(subjectName, BCStyle.CN);

            PendingCsrRequest pendingRequest = new PendingCsrRequest();
            pendingRequest.setCsrContent(csrContent);
            pendingRequest.setCommonName(commonName);
            pendingRequest.setSubmittedAt(Instant.now());
            pendingRequest.setIssuerId(issuerId);
            pendingRequest.setValidityDays(validityDays);
            pendingRequest.setOwnerId(ownerId);
            pendingCsrRepository.save(pendingRequest);

            System.out.println("✅ CSR from " + commonName + " submitted successfully. Awaiting CA approval.");
        } catch (IOException e) {
            throw new Exception("Error reading CSR file: " + e.getMessage(), e);
        }
    }

    public List<IntermediateResponse> getAllCAs() {
        List<Certificate> allCertificates = certificateRepository.findAll();

        return allCertificates.stream()
                .filter(cert -> cert.getType().equals(INTERMEDIATE) && !cert.isRevoked())
                .map(cert -> {
                    long validityDays = Duration.between(Instant.now(), cert.getNotAfter()).toDays();
                    return new IntermediateResponse(
                            cert.getSerialNumber(),
                            cert.getSubjectCommonName(),
                            cert.getIssuerCommonName(),
                            cert.getKeyStorePath(),
                            (int) validityDays
                    );
                })
                .collect(Collectors.toList());

    }

    public List<PendingCsrResponse> getPendingCsrRequestsForUser(Long userId) {
        List<Certificate> caCertificates = certificateRepository.findByOwnerId(userId)
                .stream()
                .filter(cert -> cert.getType() == CertificateType.ROOT || cert.getType() == CertificateType.INTERMEDIATE)
                .collect(Collectors.toList());

        List<String> issuerSerialNumbers = caCertificates.stream()
                .map(Certificate::getSerialNumber)
                .collect(Collectors.toList());

        List<PendingCsrRequest> pendingRequests = pendingCsrRepository.findByIssuerIdIn(issuerSerialNumbers);

        return pendingRequests.stream()
                .map(req -> new PendingCsrResponse(
                        req.getId(),
                        req.getCommonName(),
                        req.getSubmittedAt(),
                        req.getIssuerId(),
                        req.getValidityDays()
                ))
                .collect(Collectors.toList());
    }
    /*public CertificateDetails getCertificateDetails(String serialNumber) throws Exception {
        Certificate certEntity = certificateRepository.findBySerialNumber(serialNumber);
        if (certEntity == null) {
            throw new Exception("Sertifikat nije pronađen u sistemu.");
        }
        X509Certificate cert;

        // End-entity sertifikati se čuvaju kao .cer, a CA kao .p12
        if (certEntity.getType() == CertificateType.END_ENTITY) {
            try (var fis = new java.io.FileInputStream(certEntity.getKeyStorePath())) {
                java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory.getInstance("X.509");
                cert = (X509Certificate) cf.generateCertificate(fis);
            }
        } else {
            String plainPassword = encryptionService.decrypt(
                    certEntity.getKeyStorePassword(),
                    certEntity.getOwner().getSymmetricKey()
            );
            KeyStore ks = KeyStore.getInstance("PKCS12");
            try (var fis = new java.io.FileInputStream(certEntity.getKeyStorePath())) {
                ks.load(fis, plainPassword.toCharArray());
            }
            cert = (X509Certificate) ks.getCertificate(serialNumber);
        }

        if (cert == null) {
            throw new RuntimeException("Failed to load certificate from file.");
        }

        // Izvlačimo BasicConstraints
        boolean isCa = cert.getBasicConstraints() != -1;
        Integer pathLength = isCa ? cert.getBasicConstraints() : null;

        // Izvlačimo KeyUsage
        List<String> keyUsageList = new ArrayList<>();
        boolean[] keyUsage = cert.getKeyUsage();
        if (keyUsage != null) {
            if (keyUsage[0]) keyUsageList.add("digitalSignature");
            if (keyUsage[1]) keyUsageList.add("nonRepudiation");
            if (keyUsage[2]) keyUsageList.add("keyEncipherment");
            if (keyUsage[3]) keyUsageList.add("dataEncipherment");
            if (keyUsage[4]) keyUsageList.add("keyAgreement");
            if (keyUsage[5]) keyUsageList.add("keyCertSign");
            if (keyUsage[6]) keyUsageList.add("cRLSign");
            if (keyUsage[7]) keyUsageList.add("encipherOnly");
            if (keyUsage[8]) keyUsageList.add("decipherOnly");
        }

        return new CertificateDetails(isCa, pathLength, keyUsageList);
    }*/

    // Cijela metoda sa svim pomoćnim metodama

    public CertificateDetails getCertificateDetails(String serialNumber) throws Exception {
        Certificate certEntity = certificateRepository.findBySerialNumber(serialNumber);
        if (certEntity == null) {
            throw new Exception("Sertifikat nije pronađen u sistemu.");
        }
        X509Certificate cert;

        // End-entity sertifikati se čuvaju kao .cer, a CA kao .p12
        if (certEntity.getType() == CertificateType.END_ENTITY) {
            try (var fis = new java.io.FileInputStream(certEntity.getKeyStorePath())) {
                java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory.getInstance("X.509");
                cert = (X509Certificate) cf.generateCertificate(fis);
            }
        } else {
            String plainPassword = encryptionService.decrypt(
                    certEntity.getKeyStorePassword(),
                    certEntity.getOwner().getSymmetricKey()
            );
            KeyStore ks = KeyStore.getInstance("PKCS12");
            try (var fis = new java.io.FileInputStream(certEntity.getKeyStorePath())) {
                ks.load(fis, plainPassword.toCharArray());
            }
            cert = (X509Certificate) ks.getCertificate(serialNumber);
        }

        if (cert == null) {
            throw new RuntimeException("Failed to load certificate from file.");
        }

        // Izvlačimo BasicConstraints
        boolean isCa = cert.getBasicConstraints() != -1;
        Integer pathLength = isCa ? cert.getBasicConstraints() : null;

        // Izvlačimo KeyUsage
        List<String> keyUsageList = parseKeyUsage(cert.getKeyUsage());

        // Izvlačimo Extended Key Usage
        List<String> extendedKeyUsageList = cert.getExtendedKeyUsage();
        if (extendedKeyUsageList == null) {
            extendedKeyUsageList = new ArrayList<>();
        }

        // Izvlačimo Subject Alternative Names (SANs)
        Map<String, List<String>> sanMap = new HashMap<>();
        try {
            Collection<List<?>> sans = cert.getSubjectAlternativeNames();
            if (sans != null) {
                for (List<?> san : sans) {
                    Integer tag = (Integer) san.get(0);
                    Object value = san.get(1);
                    String valueString = (value instanceof byte[]) ? Arrays.toString((byte[]) value) : value.toString();

                    String type = convertSanTagToString(tag);
                    sanMap.computeIfAbsent(type, k -> new ArrayList<>()).add(valueString);
                }
            }
        } catch (CertificateParsingException e) {
            System.err.println("Greška pri parsiranju SANs: " + e.getMessage());
        }

        return new CertificateDetails(isCa, pathLength, keyUsageList, extendedKeyUsageList, sanMap);
    }

    // Pomoćna metoda za konverziju Key Usage bitova u čitljive stringove
    private List<String> parseKeyUsage(boolean[] keyUsageBits) {
        List<String> usages = new ArrayList<>();
        if (keyUsageBits == null) return usages;
        if (keyUsageBits[0]) usages.add("digitalSignature");
        if (keyUsageBits[1]) usages.add("nonRepudiation");
        if (keyUsageBits[2]) usages.add("keyEncipherment");
        if (keyUsageBits[3]) usages.add("dataEncipherment");
        if (keyUsageBits[4]) usages.add("keyAgreement");
        if (keyUsageBits[5]) usages.add("keyCertSign");
        if (keyUsageBits[6]) usages.add("cRLSign");
        if (keyUsageBits[7]) usages.add("encipherOnly");
        if (keyUsageBits[8]) usages.add("decipherOnly");
        return usages;
    }

    // Pomoćna metoda za konverziju SAN tagova u čitljive stringove
    private String convertSanTagToString(int tag) {
        switch (tag) {
            case 2: return "DNS Name";
            case 1: return "Email";
            case 6: return "URI";
            case 7: return "IP Address";
            default: return "Unknown";
        }
    }

    public String getPublicKeyAsPemForUser(User user) {
        try {
            Certificate certEntity = certificateRepository.findByOwnerId(user.getId())
                    .stream()
                    .filter(Certificate::isEncryptionCertificate)
                    .findFirst()
                    .orElseThrow(() -> new RuntimeException(
                            "Nema sertifikata za enkripciju za korisnika: " + user.getFirstName() + " " + user.getLastName()
                    ));

            // Učitajte sertifikat direktno iz .cer fajla.
            java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory.getInstance("X.509");
            java.security.cert.X509Certificate cert;
            try (FileInputStream fis = new FileInputStream(certEntity.getKeyStorePath())) {
                cert = (X509Certificate) cf.generateCertificate(fis);
            }

            // Izvuci javni ključ i konvertuj u PEM format
            PublicKey publicKey = cert.getPublicKey();
            String encoded = Base64.getEncoder().encodeToString(publicKey.getEncoded());

            StringBuilder pem = new StringBuilder();
            pem.append("-----BEGIN PUBLIC KEY-----\n");
            int index = 0;
            while (index < encoded.length()) {
                pem.append(encoded, index, Math.min(index + 64, encoded.length())).append("\n");
                index += 64;
            }
            pem.append("-----END PUBLIC KEY-----\n");

            return pem.toString();
        } catch (Exception e) {
            throw new RuntimeException("Greška pri izvlačenju public key-a za korisnika: " + user.getFirstName() + " " + user.getLastName(), e);
        }
    }
}