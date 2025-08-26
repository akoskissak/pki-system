package com.ftn.bsep.pki.service;

import com.ftn.bsep.pki.dto.SelfSignedRequest;
import com.ftn.bsep.pki.dto.SelfSignedResponse;
import com.ftn.bsep.pki.entity.Subject;
import com.ftn.bsep.pki.entity.Issuer;
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
import java.time.temporal.ChronoUnit;
import java.util.Date;

@Service
public class CertificateService {
    private final KeyStoreService keyStoreService;

    public CertificateService(KeyStoreService keyStoreService) {
        this.keyStoreService = keyStoreService;
    }

    public SelfSignedResponse createSelfSigned(SelfSignedRequest req) throws Exception {
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
        subject.setEndDate(Date.from(now.plus(10, ChronoUnit.YEARS)));
        Issuer issuer = new Issuer();
        issuer.setPrivateKey(kp.getPrivate());
        issuer.setX500Name(subjectBuilder.build());

        // Generisanje sertifikata
        X509Certificate cert = keyStoreService.generateCertificate(subject, issuer);

        // Čuvanje sertifikata
        Path p12 = keyStoreService.saveCertificate(
                cert,
                kp.getPrivate(),
                req.commonName(),
                req.password().toCharArray()
        );

        return new SelfSignedResponse("CN=" + req.commonName(), p12.toString());
    }
}