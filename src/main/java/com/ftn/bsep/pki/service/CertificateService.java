package com.ftn.bsep.pki.service;

import com.ftn.bsep.pki.dto.*;
import com.ftn.bsep.pki.entity.*;
import com.ftn.bsep.pki.entity.Certificate;
import com.ftn.bsep.pki.repository.ICertificateRepository;
import com.ftn.bsep.pki.repository.ICertificateTemplateRepository;
import com.ftn.bsep.pki.repository.IPendingCsrRepository;
import com.ftn.bsep.pki.repository.IUserRepository;
import org.apache.commons.lang3.RandomStringUtils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.util.IPAddress;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Map;

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
import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.net.MalformedURLException;


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
    private final ICertificateTemplateRepository templateRepository;
    private static final Logger logger = LoggerFactory.getLogger(CertificateService.class);

    public CertificateService(KeyStoreService keyStoreService, ICertificateRepository certificateRepository, IUserRepository userRepository, EncryptionService encryptionService, IPendingCsrRepository pendingCsrRepository, ICertificateTemplateRepository templateRepository) {
        this.keyStoreService = keyStoreService;
        this.userRepository = userRepository;
        this.encryptionService = encryptionService;
        this.certificateRepository = certificateRepository;
        this.pendingCsrRepository = pendingCsrRepository;
        this.templateRepository = templateRepository;
    }

    public SelfSignedResponse createSelfSigned(SelfSignedRequest req) throws Exception {
        logger.info("Pokrenuto kreiranje self-signed sertifikata za userId={}", req.ownerId());

        User owner = userRepository.findById(req.ownerId())
                .orElseThrow(() -> {
                    logger.error("User sa ID={} nije pronadjen", req.ownerId());
                    return new RuntimeException("User not found");
                });

        if (owner.getSymmetricKey() == null || owner.getSymmetricKey().isEmpty()) {
            logger.error("User sa ID={} nema simetricni kljuc za enkripciju", req.ownerId());
            throw new IllegalStateException("User does not have a symmetric key for encryption.");
        }

        logger.info("Generisanje RSA kljucnog para...");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        logger.info("RSA kljucni par generisan");

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

        logger.info("Generisanje X509 sertifikata za CN={}", req.commonName());
        X509Certificate cert = keyStoreService.generateCertificate(subject, issuer, CertificateType.ROOT, req.extensions(), req.subjectAlternativeNames());
        logger.info("Sertifikat generisan sa serialNumber={}", cert.getSerialNumber());
        X509Certificate[] chain = { cert };

        String keyStorePassword = RandomStringUtils.randomAlphanumeric(16);

        logger.info("Keystore lozinka za testiranje je: {}", keyStorePassword);

        Path p12 = keyStoreService.saveCertificateChain(
                chain,
                kp.getPrivate(),
                cert.getSerialNumber().toString(),
                keyStorePassword.toCharArray()
        );
        logger.info("Sertifikat sacuvan u keystore: {}", p12);
        //String encryptedPassword = encryptionService.encrypt(keyStorePassword, owner.getSymmetricKey());

        String encryptedUserKey = owner.getSymmetricKey();
        String plainUserKey = encryptionService.decryptUserKey(encryptedUserKey);
        // enkripcija ključa pomoću dekriptovanog simetričnog ključa korisnika
        String encryptedPassword = encryptionService.encrypt(keyStorePassword, plainUserKey);
        logger.info("Keystore lozinka enkriptovana za userId={}", req.ownerId());

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
        logger.info("Sertifikat sacuvan u bazi za userId={} sa serialNumber={}", req.ownerId(), cert.getSerialNumber());

        return new SelfSignedResponse("CN=" + req.commonName(), p12.toString());
    }

    public Certificate issueIntermediate(IntermediateRequest req) throws Exception {
        logger.info("Pokretanje issueIntermediate za CN={}", req.commonName());
        
        // --- Učitavanje issuer sertifikata ---
        Long issuerId = req.issuerId();
        Certificate issuerCertEntity = certificateRepository.findById(req.issuerId())
                .orElseThrow(() -> {
                            logger.error("Issuer certificate sa ID={} nije pronađen", issuerId);
                            return new RuntimeException("Issuer certificate not found");
                });
        
        logger.info("Issuer cert entity loaded: serialNumber={}", issuerCertEntity.getSerialNumber());

        try {
            Set<String> permittedExtensions = getPermittedExtensions(issuerCertEntity);
            List<String> requestedExtensions = req.extensions() != null ? req.extensions() : new ArrayList<>();

            // Ako se koristi šablon, njegove ekstenzije se spajaju sa onima iz zahtjeva
            if (req.templateId() != null) {
                CertificateTemplate template = templateRepository.findById(req.templateId()).orElseThrow();
                Set<String> finalExtensions = new HashSet<>(requestedExtensions);
                if(template.getKeyUsage() != null) finalExtensions.addAll(Arrays.asList(template.getKeyUsage().split(",")));
                if(template.getExtendedKeyUsage() != null) finalExtensions.addAll(Arrays.asList(template.getExtendedKeyUsage().split(",")));
                requestedExtensions = new ArrayList<>(finalExtensions);
            }

            // Provjera da li su sve tražene ekstenzije dozvoljene
            if (!permittedExtensions.containsAll(requestedExtensions)) {
                List<String> forbidden = new ArrayList<>(requestedExtensions);
                forbidden.removeAll(permittedExtensions);
                throw new SecurityException("Request contains extensions not permitted by the issuer. Forbidden extensions: " + forbidden);
            }
            System.out.println("✅ Extension policy validation successful.");
        } catch (Exception e) {
            System.out.println("❌ Extension policy validation FAILED: " + e.getMessage());
            throw e;
        }

        if (issuerCertEntity.isRevoked()) {
            logger.error("Issuer certificate sa serialNumber={} je opozvan", issuerCertEntity.getSerialNumber());
            throw new Exception("Issuer certificate is revoked");
        }

        Instant now = Instant.now();
        System.out.println("Now: " + now);
        logger.debug("Issuer validity period: {} - {}", issuerCertEntity.getNotBefore(), issuerCertEntity.getNotAfter());

        if (now.isBefore(issuerCertEntity.getNotBefore()) || now.isAfter(issuerCertEntity.getNotAfter())) {
            logger.error("Issuer certificate trenutno nije validan: serialNumber={}", issuerCertEntity.getSerialNumber());
            throw new Exception("Issuer certificate is not valid currently.");
        }
        Long issuerOwnerId = req.issuerOwnerId();
        User issuerOwner = userRepository.findById(req.issuerOwnerId())
                .orElseThrow(() -> {
                            logger.error("Issuer owner sa ID={} nije pronađen", issuerOwnerId);
                            return new RuntimeException("Issuer owner not found");
                        });

        logger.info("Issuer owner loaded: {}", issuerOwner.getEmail());

        /*String plainPassword = encryptionService.decrypt(
                issuerCertEntity.getKeyStorePassword(),
                issuerOwner.getSymmetricKey()
        );*/

        String plainPassword = getDecryptedKeystorePassword(issuerCertEntity);
        logger.debug("Decrypted keystore password length: {}", plainPassword.length());

        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (var fis = new java.io.FileInputStream(issuerCertEntity.getKeyStorePath())) {
            ks.load(fis, plainPassword.toCharArray());
        }
        logger.info("Keystore učitan sa: {}", issuerCertEntity.getKeyStorePath());

        // --- Preuzimanje sertifikata izdavaoca ---
        String issuerAlias = issuerCertEntity.getSerialNumber();
        logger.debug("Koristi se alias za sertifikat: {}", issuerAlias);

        X509Certificate issuerCert = (X509Certificate) ks.getCertificate(issuerAlias);
        if (issuerCert == null) {
            logger.error("Issuer certificate nije pronađen u keystore-u sa alias-om: {}", issuerAlias);
            throw new RuntimeException("Issuer certificate not found in keystore.");
        }
        if (issuerCert.getBasicConstraints() == -1) {
            logger.error("Sertifikat izdavaoca {} nije CA", issuerCert.getSubjectX500Principal());
            throw new Exception("Sertifikat izdavaoca (" + issuerCert.getSubjectX500Principal().getName() + ") nije CA i ne može da izdaje druge sertifikate.");
        }

        boolean[] keyUsage = issuerCert.getKeyUsage();
        // Prema X.509 standardu, 'keyCertSign' je na indeksu 5.
        if (keyUsage != null && !keyUsage[5]) {
            logger.error("Issuer certificate nema keyCertSign dozvolu");
            throw new Exception("Sertifikat izdavaoca nema 'keyCertSign' dozvolu i ne može da potpisuje druge sertifikate.");
        }
        logger.info("Provere CA i KeyUsage izdavaoca su uspešne: {}", issuerCert.getSubjectX500Principal());

        java.security.cert.Certificate[] issuerChain = ks.getCertificateChain(issuerAlias);
        if (issuerChain == null || issuerChain.length == 0) {
            logger.warn("Issuer chain je prazan, koristi se samo pojedinačni sertifikat");
            issuerChain = new java.security.cert.Certificate[]{issuerCert};
        }
        System.out.println("Issuer chain length: " + issuerChain.length);

        // --- Validacija chain-a ---
        try {
            validateCertificateChain(issuerChain);
            logger.info("Issuer chain validated OK");
        } catch (Exception e) {
            logger.error("validateCertificateChain failed: {}", e.getMessage());
            throw e;
        }

        PrivateKey issuerPrivateKey = (PrivateKey) ks.getKey(issuerAlias, plainPassword.toCharArray());
        logger.debug("Issuer private key loaded: {}", issuerPrivateKey != null);

        System.out.println("Loaded issuer private key: " + (issuerPrivateKey != null));
        CertificateTemplate template = null;
        if (req.templateId() != null) {
            template = templateRepository.findById(req.templateId())
                    .orElseThrow(() -> new RuntimeException("Template not found"));

            // 1️⃣ Validacija CN
            if (!req.commonName().matches(template.getCnRegex())) {
                throw new RuntimeException("Common Name does not match template regex: " + template.getCnRegex());
            }

            // 2️⃣ Validacija SAN
            if (req.subjectAlternativeNames() != null && template.getSanRegex() != null && !template.getSanRegex().isEmpty()) {
                ObjectMapper objectMapper = new ObjectMapper();
                Map<String, String> sanRegexMap = objectMapper.readValue(template.getSanRegex(), new TypeReference<>() {});

                for (SanDto san : req.subjectAlternativeNames()) {
                    String regex = sanRegexMap.get(san.getType().toUpperCase());

                    if (regex != null && !regex.trim().isEmpty()) {
                        if (!san.getValue().matches(regex)) {
                            throw new SecurityException(
                                    "SAN value '" + san.getValue() + "' for type " + san.getType() +
                                            " does not match template policy regex: " + regex
                            );
                        }
                    }
                }
            }

            // 3️⃣ Validacija TTL
            if (req.validityDays() > template.getTtlDays()) {
                throw new RuntimeException("Validity exceeds template TTL: " + template.getTtlDays() + " days");
            }

            // 4️⃣ Postavljanje default ekstenzija ako nisu zadate
            List<String> exts = req.extensions();
            if ((exts == null || exts.isEmpty()) && template.getKeyUsage() != null) {
                exts = List.of(template.getKeyUsage().split(","));
            }

            List<SanDto> sans = req.subjectAlternativeNames();
            if (sans == null) sans = List.of();

            // Extended Key Usage
            if (template.getExtendedKeyUsage() != null) {
                List<String> eku = List.of(template.getExtendedKeyUsage().split(","));
                exts = new ArrayList<>(exts);
                exts.addAll(eku);
            }

            req = new IntermediateRequest(
                    req.issuerId(),
                    req.issuerOwnerId(),
                    req.commonName(),
                    req.organization(),
                    req.organizationalUnit(),
                    req.country(),
                    req.validityDays(),
                    exts,
                    sans,
                    req.templateId()
            );
        }

        // --- Kreiranje novog sertifikata ---
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair subjectKeyPair = kpg.generateKeyPair();
        logger.info("Generated subject keypair");

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
        logger.debug("Issuer X500Name: {}", issuer.getX500Name());

        X509Certificate newCert = keyStoreService.generateCertificate(
                subject, issuer, INTERMEDIATE, req.extensions(), req.subjectAlternativeNames()
        );
        logger.info("Generated new intermediate certificate: {}", newCert.getSerialNumber());
        logger.debug("New cert subject: {}, issuer: {}", newCert.getSubjectX500Principal(), newCert.getIssuerX500Principal());

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
            logger.info("Digital signature check PASSED");
        } catch (Exception e) {
            logger.error("Digital signature check FAILED: {}", e.getMessage());
            throw new RuntimeException("Digital signature of new certificate is invalid: " + e.getMessage());
        }

        String keyStorePassword = RandomStringUtils.randomAlphanumeric(16);
        Path p12 = keyStoreService.saveCertificateChain(
                fullChain,
                subjectKeyPair.getPrivate(),
                newCert.getSerialNumber().toString(),
                keyStorePassword.toCharArray()
        );
        logger.info("Saved new keystore: {}", p12);

        //String encryptedPassword = encryptionService.encrypt(keyStorePassword, issuerOwner.getSymmetricKey());
        String encryptedUserKey = issuerOwner.getSymmetricKey();
        String plainUserKey = encryptionService.decryptUserKey(encryptedUserKey);
        String encryptedPassword = encryptionService.encrypt(keyStorePassword, plainUserKey);

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
                logger.error("CA user {} ne može izdavati sertifikat za drugu organizaciju", issuerOwner.getEmail());
                throw new RuntimeException("CA user cannot issue certificate for another organization");
            }
        }

        // --- Ograničenje trajanja sertifikata ---
        Instant requestedNotAfter = now.plus(req.validityDays(), ChronoUnit.DAYS);
        if (requestedNotAfter.isAfter(issuerCertEntity.getNotAfter())) {
            logger.error("Requested certificate expiry {} je posle issuer cert expiry {}", requestedNotAfter, issuerCertEntity.getNotAfter());
            throw new RuntimeException("Cannot issue certificate that expires after the issuer certificate");
        }
        
        logger.info("Intermediate certificate created successfully: {}", entity.getSerialNumber());

        return certificateRepository.save(entity);
    }

    public Certificate issueEndEntity(EndEntityRequest req, Long ownerId, boolean isEncryptionCertificate) throws Exception {
        logger.info("Pokrenuto izdavanje End-Entity sertifikata za CN={} (ownerId={})", req.commonName(), ownerId);
        
        Certificate issuerCertEntity = certificateRepository.findById(req.issuerId())
                .orElseThrow(() -> {
                    logger.error("Issuer sertifikat sa ID={} nije pronađen", req.issuerId());
                    return new RuntimeException("Issuer certificate not found");
                });

        logger.info("Issuer cert entity loaded: serialNumber={}", issuerCertEntity.getSerialNumber());

        if (issuerCertEntity.isRevoked()) {
            logger.error("Issuer certificate serialNumber={} je opozvan", issuerCertEntity.getSerialNumber());
            throw new Exception("Issuer certificate is revoked");
        }

        Instant now = Instant.now();
        Instant requestedEndDate = now.plus(req.validityDays(), ChronoUnit.DAYS);
        Instant issuerEndDate = issuerCertEntity.getNotAfter();

        if (requestedEndDate.isAfter(issuerEndDate)) {
            logger.error("Traženi sertifikat CN={} traži validity {} koji prelazi validity issuer sertifikata {}",
                    req.commonName(), requestedEndDate, issuerEndDate);
            throw new IllegalArgumentException(
                    "Certificate validity cannot extend beyond the issuer's validity period. Issuer expires on: " + issuerEndDate
            );
        }

        User issuerOwner = userRepository.findById(req.issuerOwnerId())
                .orElseThrow(() -> {
                    logger.error("Issuer owner sa ID={} nije pronađen", req.issuerOwnerId());
                    return new RuntimeException("Issuer owner not found");
                });
        logger.info("Issuer owner loaded: {}", issuerOwner.getEmail());

        User owner = userRepository.findById(ownerId)
                .orElseThrow(() -> {
                    logger.error("Owner user sa ID={} nije pronađen", ownerId);

                    return new RuntimeException("Owner not found");
                });
        
        logger.info("End-Entity sertifikat će pripadati korisniku: {}", owner.getEmail());

        /*String plainPassword = encryptionService.decrypt(
                issuerCertEntity.getKeyStorePassword(),
                issuerOwner.getSymmetricKey()
        );*/

        String plainPassword = getDecryptedKeystorePassword(issuerCertEntity);
        logger.info("Intermediate CA sifra je za AKOS-: {}", plainPassword);
        logger.debug("Dekriptovan password za issuer keystore (dužina={})", plainPassword.length());

        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (var fis = new java.io.FileInputStream(issuerCertEntity.getKeyStorePath())) {
            ks.load(fis, plainPassword.toCharArray());
        }
        logger.info("Keystore issuer sertifikata učitan sa putanje: {}", issuerCertEntity.getKeyStorePath());

        String issuerAlias = issuerCertEntity.getSerialNumber();
        X509Certificate issuerCert = (X509Certificate) ks.getCertificate(issuerAlias);
        PrivateKey issuerPrivateKey = (PrivateKey) ks.getKey(issuerAlias, plainPassword.toCharArray());
        logger.info("Issuer sertifikat i privatni ključ uspešno učitani (alias={})", issuerAlias);

        
        byte[] publicKeyBytes = Base64.getDecoder().decode(req.publicKey());
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey subjectPublicKey = kf.generatePublic(new X509EncodedKeySpec(publicKeyBytes));
        logger.info("Subject javni ključ dekodiran iz request-a za CN={}", req.commonName());

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
        logger.debug("Issuer X500Name: {}", issuer.getX500Name());
        
        X509Certificate newCert = keyStoreService.generateEECertificate(
                subject, issuer, CertificateType.END_ENTITY, req.extensions(), req.subjectAlternativeNames()
        );
        logger.info("End-Entity sertifikat generisan: serialNumber={}, subjectCN={}, issuerCN={}",
                newCert.getSerialNumber(), newCert.getSubjectX500Principal(), newCert.getIssuerX500Principal());

        Path certPath = keyStoreService.saveEECertificate(newCert);
        logger.info("End-Entity sertifikat sačuvan na: {}", certPath);

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
        
        logger.info("End-Entity sertifikat uspešno kreiran i sačuvan u bazi: serialNumber={}", entity.getSerialNumber());

        return certificateRepository.save(entity);
    }

    public Certificate issueFromPendingCsr(Long requestId) throws Exception {
        logger.info("Starting issueFromPendingCsr for requestId={}", requestId);
        
        PendingCsrRequest pendingRequest = pendingCsrRepository.findById(requestId)
                .orElseThrow(() -> {
                    logger.error("Pending CSR request with id={} not found", requestId);
                    return new IllegalArgumentException("Pending CSR request with id " + requestId + " not found.");
                });
        logger.debug("Loaded PendingCsrRequest id={}, ownerId={}, issuerId={}",
                pendingRequest.getId(), pendingRequest.getOwnerId(), pendingRequest.getIssuerId());

        
        PKCS10CertificationRequest csr;
        try (PEMParser pemParser = new PEMParser(new StringReader(pendingRequest.getCsrContent()))) {
            Object parsedObject = pemParser.readObject();
            if (!(parsedObject instanceof PKCS10CertificationRequest)) {
                logger.error("Invalid CSR content for requestId={}", requestId);
                throw new IllegalArgumentException("Invalid CSR content in database for request " + requestId);
            }
            csr = (PKCS10CertificationRequest) parsedObject;
        }
        logger.info("CSR successfully parsed for requestId={}", requestId);
        
        JcaPKCS10CertificationRequest jcaCSR = new JcaPKCS10CertificationRequest(csr);
        PublicKey publicKey = jcaCSR.getPublicKey();
        X500Name subjectName = jcaCSR.getSubject();
        logger.debug("CSR subjectName={}, publicKeyAlgorithm={}", subjectName, publicKey.getAlgorithm());

        String commonName = getRdnString(subjectName, BCStyle.CN);
        String surname = getRdnString(subjectName, BCStyle.SURNAME);
        String givenname = getRdnString(subjectName, BCStyle.GIVENNAME);
        String organization = getRdnString(subjectName, BCStyle.O);
        String organizationalUnit = getRdnString(subjectName, BCStyle.OU);
        String country = getRdnString(subjectName, BCStyle.C);
        logger.info("Extracted subject info from CSR: CN={}, O={}, OU={}, C={}",
                commonName, organization, organizationalUnit, country);

        if (!jcaCSR.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(publicKey))) {
            logger.error("CSR signature is invalid for requestId={}", requestId);
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

        List<SanDto> subjectAlternativeNames = new ArrayList<>();
        if (extensions != null) {
            Extension sanExtension = extensions.getExtension(Extension.subjectAlternativeName);
            if (sanExtension != null) {
                GeneralNames generalNames = GeneralNames.getInstance(sanExtension.getParsedValue());
                for (GeneralName name : generalNames.getNames()) {
                    String value = name.getName().toString();
                    String type;
                    switch (name.getTagNo()) {
                        case GeneralName.dNSName:
                            type = "DNS";
                            break;
                        case GeneralName.iPAddress:
                            try {
                                byte[] ipBytes = org.bouncycastle.asn1.ASN1OctetString.getInstance(name.getName()).getOctets();

                                value = java.net.InetAddress.getByAddress(ipBytes).getHostAddress();
                                type = "IP";
                            } catch (java.net.UnknownHostException e) {
                                System.err.println("Greška pri parsiranju IP adrese iz SAN-a: " + e.getMessage());
                                continue;
                            }
                            break;
                        case GeneralName.rfc822Name:
                            type = "EMAIL";
                            break;
                        case GeneralName.uniformResourceIdentifier:
                            type = "URI";
                            break;
                        default:
                            continue; // Preskoči nepoznate tipove
                    }
                    subjectAlternativeNames.add(new SanDto(type, value));
                }
            }
        }

        logger.debug("CSR requested extensions: {}", extList);
        
        Certificate caCert = certificateRepository.findBySerialNumber(pendingRequest.getIssuerId());
        if (caCert == null) {
            logger.error("Issuer CA not found for issuerId={}", pendingRequest.getIssuerId());
            throw new IllegalArgumentException("Issuer CA not found.");
        }
        logger.info("Issuer CA loaded: serialNumber={}, subjectCN={}, ownerId={}",
                caCert.getSerialNumber(), caCert.getSubjectCommonName(), caCert.getOwner().getId());

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
                extList,
                subjectAlternativeNames
        );

        Long ownerId =  pendingRequest.getOwnerId();
        logger.info("Deleting PendingCsrRequest id={} before issuing certificate", requestId);
        pendingCsrRepository.deleteById(requestId);

        logger.info("Forwarding to issueEndEntity for subject CN={} (ownerId={})", commonName, ownerId);

        return this.issueEndEntity(req, ownerId, isEncryptionCertificate);
    }

    private String getRdnString(X500Name subjectName, ASN1ObjectIdentifier rdnType) {
        RDN[] rdns = subjectName.getRDNs(rdnType);
        if (rdns.length > 0) {
            return IETFUtils.valueToString(rdns[0].getFirst().getValue());
        }
        return "";
    }


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
        logger.info("User id={}, email={}, role={} is requesting certificates",
                user.getId(), user.getEmail(), role);
        
        if ("ADMIN".equals(role)) {
            return certificateRepository.findAll();
        } else if ("CA_USER".equals(role)) {
            return certificateRepository.findAllByOrganization(user.getOrganization());
        } else if ("END_USER".equals(role)) {
            return certificateRepository.findByOwnerId(user.getId());
        } else {
            logger.warn("Unauthorized or unknown role={} for userId={}, returning empty list",
                    role, user.getId());
        }

        return new ArrayList<>();
    }

    public void handlePendingCsr(MultipartFile csrFile, String issuerId, Integer validityDays, Long ownerId) throws Exception {
        logger.info("Received CSR submission request: ownerId={}, issuerId={}, requestedValidity={} days",
                ownerId, issuerId, validityDays);
        
        Certificate caCert = certificateRepository.findBySerialNumber(issuerId);
        if (caCert == null) {
            logger.error("CSR submission failed: issuerId={} not found (ownerId={})", issuerId, ownerId);
            throw new IllegalArgumentException("Issuer CA not found.");
        }

        long caRemainingDays = Duration.between(Instant.now(), caCert.getNotAfter()).toDays();
        if (validityDays > caRemainingDays) {
            logger.warn("CSR rejected: requested validity {} exceeds CA remaining validity {} (issuerId={}, ownerId={})",
                    validityDays, caRemainingDays, issuerId, ownerId);
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
                    logger.error("Invalid CSR file submitted by ownerId={}, issuerId={}", ownerId, issuerId);
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

            logger.info("CSR submission successful: commonName={}, issuerId={}, validityDays={}, ownerId={}",
                    commonName, issuerId, validityDays, ownerId);
        } catch (IOException e) {
            logger.error("Error reading CSR file for ownerId={}, issuerId={}: {}", ownerId, issuerId, e.getMessage());
            throw new Exception("Error reading CSR file: " + e.getMessage(), e);
        }
    }

    public List<IntermediateResponse> getAllCAs() {
        logger.info("Fetching all active intermediate CA certificates");
        List<Certificate> allCertificates = certificateRepository.findAll();

        List<IntermediateResponse> responses = allCertificates.stream()
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
        logger.info("Returning {} intermediate CA certificates", responses.size());
        
        return responses;
    }

    public List<PendingCsrResponse> getPendingCsrRequestsForUser(Long userId) {
        logger.info("Fetching pending CSR requests for userId={}", userId);
        
        List<Certificate> caCertificates = certificateRepository.findByOwnerId(userId)
                .stream()
                .filter(cert -> cert.getType() == CertificateType.ROOT || cert.getType() == CertificateType.INTERMEDIATE)
                .collect(Collectors.toList());

        List<String> issuerSerialNumbers = caCertificates.stream()
                .map(Certificate::getSerialNumber)
                .collect(Collectors.toList());

        List<PendingCsrRequest> pendingRequests = pendingCsrRepository.findByIssuerIdIn(issuerSerialNumbers);

        List<PendingCsrResponse> responses = pendingRequests.stream()
                .map(req -> new PendingCsrResponse(
                        req.getId(),
                        req.getCommonName(),
                        req.getSubmittedAt(),
                        req.getIssuerId(),
                        req.getValidityDays()
                ))
                .collect(Collectors.toList());
        
        logger.info("Found {} pending CSR requests for userId={}", responses.size(), userId);

        return responses;
    }

    public Set<String> getPermittedExtensionsForIssuer(Long issuerId) {
        try {
            Certificate issuerEntity = certificateRepository.findById(issuerId)
                    .orElseThrow(() -> new RuntimeException("Issuer not found with ID: " + issuerId));

            return getPermittedExtensions(issuerEntity);
        } catch (Exception e) {
            throw new RuntimeException("Failed to get permitted extensions for issuer " + issuerId, e);
        }
    }

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
            /*String plainPassword = encryptionService.decrypt(
                    certEntity.getKeyStorePassword(),
                    certEntity.getOwner().getSymmetricKey()
            );*/

            String plainPassword = getDecryptedKeystorePassword(certEntity);
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
            logger.info("Loaded details for certificate SN={}", serialNumber);
        } catch (CertificateParsingException e) {
            logger.error("Error loading certificate SN={}: {}", serialNumber, e.getMessage(), e);
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


    private Set<String> getPermittedExtensions(Certificate issuerEntity) throws Exception {
        // Učitavamo X509 sertifikat issuera
        /*String plainPassword = encryptionService.decrypt(
                issuerEntity.getKeyStorePassword(),
                issuerEntity.getOwner().getSymmetricKey()
        );*/
        String plainPassword = getDecryptedKeystorePassword(issuerEntity);
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (var fis = new java.io.FileInputStream(issuerEntity.getKeyStorePath())) {
            ks.load(fis, plainPassword.toCharArray());
        }
        X509Certificate issuerCert = (X509Certificate) ks.getCertificate(issuerEntity.getSerialNumber());
        if (issuerCert == null) {
            throw new RuntimeException("Issuer certificate not found in keystore.");
        }

        // Izvlačimo sve dozvoljene ekstenzije koje issuer ima u Set
        Set<String> permittedExtensions = new HashSet<>();
        boolean[] ku = issuerCert.getKeyUsage();
        if (ku != null) {
            if (ku[0]) permittedExtensions.add("digitalSignature");
            if (ku[1]) permittedExtensions.add("nonRepudiation");
            if (ku[2]) permittedExtensions.add("keyEncipherment");
            if (ku[3]) permittedExtensions.add("dataEncipherment");
        }
        List<String> ekuOids = issuerCert.getExtendedKeyUsage();
        if (ekuOids != null) {
            for (String oid : ekuOids) {
                if (oid.equals("1.3.6.1.5.5.7.3.1")) permittedExtensions.add("serverAuth");
                if (oid.equals("1.3.6.1.5.5.7.3.2")) permittedExtensions.add("clientAuth");
                if (oid.equals("1.3.6.1.5.5.7.3.3")) permittedExtensions.add("codeSigning");
                if (oid.equals("1.3.6.1.5.5.7.3.4")) permittedExtensions.add("emailProtection");
            }
        }
        return permittedExtensions;
    }

    public String getPublicKeyAsPemForUser(User user) {
        logger.info("Request to get public key PEM for user: id={}, name={} {}",
                user.getId(), user.getFirstName(), user.getLastName());
        
        try {
            Certificate certEntity = certificateRepository.findByOwnerId(user.getId())
                    .stream()
                    .filter(Certificate::isEncryptionCertificate)
                    .findFirst()
                    .orElseThrow(() -> {
                        logger.error("No encryption certificate found for user id={} ({}) {}",
                                user.getId(), user.getFirstName(), user.getLastName());

                        return new RuntimeException(
                                        "Nema sertifikata za enkripciju za korisnika: " + user.getFirstName() + " " + user.getLastName()
                                );
                    });

            logger.debug("Found encryption certificate: id={}, serialNumber={}, path={}",
                    certEntity.getId(), certEntity.getSerialNumber(), certEntity.getKeyStorePath());

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
            
            logger.info("Successfully extracted public key PEM for user id={} (serialNumber={})",
                    user.getId(), certEntity.getSerialNumber());

            return pem.toString();
        } catch (Exception e) {
            logger.error("Failed to get public key PEM for user id={} {} {}: {}",
                    user.getId(), user.getFirstName(), user.getLastName(), e.getMessage(), e);
            throw new RuntimeException("Greška pri izvlačenju public key-a za korisnika: " + user.getFirstName() + " " + user.getLastName(), e);
        }

    }

    public Resource loadCertificateResource(String serialNumber) {
        // 1. Pronađi sertifikat u bazi na osnovu serijskog broja
        Certificate certEntity = certificateRepository.findBySerialNumber(serialNumber);
        if (certEntity == null) {
            throw new RuntimeException("Sertifikat sa serijskim brojem " + serialNumber + " nije pronađen.");
        }

        // 2. Proveri da li je u pitanju CA sertifikat (ROOT ili INTERMEDIATE)
        if (certEntity.getType() != CertificateType.ROOT && certEntity.getType() != CertificateType.INTERMEDIATE) {
            throw new RuntimeException("Ovaj endpoint je namenjen samo za CA sertifikate.");
        }

        try {
            // 3. Uzmi punu putanju do .p12 fajla iz baze
            Path filePath = Paths.get(certEntity.getKeyStorePath());
            Resource resource = new UrlResource(filePath.toUri());

            if (resource.exists() && resource.isReadable()) {
                return resource;
            } else {
                throw new RuntimeException("Fajl sertifikata nije pronađen ili se ne može pročitati na putanji: " + filePath);
            }
        } catch (MalformedURLException e) {
            throw new RuntimeException("Greška prilikom kreiranja putanje do fajla.", e);
        }
    }
    private String getDecryptedKeystorePassword(Certificate certEntity) throws Exception {
        // Tražimo enkriptovani ključ korisnika
        String encryptedUserKey = certEntity.getOwner().getSymmetricKey();
        if (encryptedUserKey == null || encryptedUserKey.isEmpty()) {
            throw new IllegalStateException("Korisnik " + certEntity.getOwner().getEmail() + " nema dodeljen simetrični ključ.");
        }

        // Dekriptujemo pomoću glavnog ključa
        String plainUserKey = encryptionService.decryptUserKey(encryptedUserKey);

        // Pomoću njega dekriptujemo lozinku od keystore-a
        return encryptionService.decrypt(certEntity.getKeyStorePassword(), plainUserKey);
    }
}