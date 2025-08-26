package com.ftn.bsep.pki.service;

import com.ftn.bsep.pki.dto.SelfSignedRequest;
import com.ftn.bsep.pki.dto.SelfSignedResponse;
import com.ftn.bsep.pki.entity.*;
import com.ftn.bsep.pki.repository.ICertificateRepository;
import com.ftn.bsep.pki.repository.IUserRepository;
import org.apache.commons.lang3.RandomStringUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Date;

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

        // Provera da li korisnik ima simetrični ključ
        if (owner.getSymmetricKey() == null || owner.getSymmetricKey().isEmpty()) {
            throw new IllegalStateException("User does not have a symmetric key for encryption.");
        }

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        // Kreiranje X500Name za Subjekta (vlasnika)
        X500NameBuilder subjectBuilder = new X500NameBuilder(BCStyle.INSTANCE);
        subjectBuilder.addRDN(BCStyle.CN, req.commonName());
        subjectBuilder.addRDN(BCStyle.SURNAME, req.surname());
        subjectBuilder.addRDN(BCStyle.GIVENNAME, req.givenname());
        subjectBuilder.addRDN(BCStyle.O, req.organization());
        subjectBuilder.addRDN(BCStyle.OU, req.organizationalUnit());
        subjectBuilder.addRDN(BCStyle.C, req.country());

        // Kreiranje Subject i Issuer modela
        // U ovom slučaju, Issuer je isti kao i Subject (self-signed)
        Instant now = Instant.now();
        Subject subject = new Subject();
        subject.setPublicKey(kp.getPublic());
        subject.setX500Name(subjectBuilder.build());
        subject.setSerialNumber(new BigInteger(64, new SecureRandom()));
        subject.setStartDate(Date.from(now));
        //subject.setEndDate(Date.from(now.plus(10, ChronoUnit.YEARS)));
        ZonedDateTime tenYearsFromNow = ZonedDateTime.ofInstant(now, ZoneId.systemDefault()).plusYears(10);
        subject.setEndDate(Date.from(tenYearsFromNow.toInstant()));

        Issuer issuer = new Issuer();
        issuer.setPrivateKey(kp.getPrivate());
        issuer.setX500Name(subjectBuilder.build());

        // Generisanje sertifikata
        X509Certificate cert = keyStoreService.generateCertificate(subject, issuer);

        // Čuvanje sertifikata
        /*Path p12 = keyStoreService.saveCertificate(
                cert,
                kp.getPrivate(),
                req.commonName(),
                req.password().toCharArray()
        );*/

        // 2. Kreiraj lanac (za root, sadrži samo njega)
        X509Certificate[] chain = { cert };

        // 3. Generiši nasumičnu lozinku za keystore
        String keyStorePassword = RandomStringUtils.randomAlphanumeric(16);

        // 4. Sačuvaj sertifikat i lanac u keystore
        Path p12 = keyStoreService.saveCertificateChain(
                chain,
                kp.getPrivate(),
                req.commonName(),
                keyStorePassword.toCharArray()
        );


        // 5. Enkriptuj lozinku koristeći simetrični ključ specifičan za korisnika
        String encryptedPassword = encryptionService.encrypt(keyStorePassword, owner.getSymmetricKey());

        // 6. Sačuvaj entitet u bazu
        Certificate certificateEntity = new Certificate();

        certificateEntity.setSerialNumber(cert.getSerialNumber().toString());
        certificateEntity.setSubjectCommonName(req.commonName());
        certificateEntity.setSubjectSurname(req.surname());
        certificateEntity.setSubjectGivenname(req.givenname());
        certificateEntity.setSubjectOrganization(req.organization());
        certificateEntity.setSubjectOrganizationalUnit(req.organizationalUnit());
        certificateEntity.setSubjectCountry(req.country());
        certificateEntity.setIssuerCommonName(req.commonName()); // Self-signed
        certificateEntity.setIssuerOrganization(req.organization()); // Self-signed
        certificateEntity.setNotBefore(cert.getNotBefore().toInstant());
        certificateEntity.setNotAfter(cert.getNotAfter().toInstant());
        certificateEntity.setType(CertificateType.ROOT);
        certificateEntity.setParentCertificate(null); // Root nema roditelja
        certificateEntity.setRevoked(false);
        certificateEntity.setKeyStorePath(p12.toString());
        certificateEntity.setKeyStorePassword(encryptedPassword);

        certificateRepository.save(certificateEntity);

        return new SelfSignedResponse("CN=" + req.commonName(), p12.toString());
    }
}