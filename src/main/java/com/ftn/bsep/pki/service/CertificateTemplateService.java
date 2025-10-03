package com.ftn.bsep.pki.service;

import com.ftn.bsep.pki.dto.CertificateTemplateRequest;
import com.ftn.bsep.pki.dto.CertificateTemplateResponse;
import com.ftn.bsep.pki.entity.Certificate;
import com.ftn.bsep.pki.entity.CertificateTemplate;
import com.ftn.bsep.pki.repository.ICertificateRepository;
import com.ftn.bsep.pki.repository.ICertificateTemplateRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import java.util.List;

@Service
public class CertificateTemplateService {
    private final ICertificateTemplateRepository templateRepository;
    private final ICertificateRepository certificateRepository;
    private final EncryptionService encryptionService;
    private static final Logger logger = LoggerFactory.getLogger(CertificateTemplateService.class);
    
    public CertificateTemplateService(ICertificateTemplateRepository templateRepository,
                                      ICertificateRepository certificateRepository, EncryptionService encryptionService) {
        this.templateRepository = templateRepository;
        this.certificateRepository = certificateRepository;
        this.encryptionService = encryptionService;
    }
    public CertificateTemplateResponse create(CertificateTemplateRequest req) {
        logger.info("Request to create certificate template: name='{}', issuerId={}", req.name(), req.issuerId());

        Certificate issuer = certificateRepository.findById(req.issuerId())
                .orElseThrow(() -> {
                    logger.error("Failed to create template. Issuer with id={} not found.", req.issuerId());

                    return new RuntimeException("Issuer not found");
                });

        validateExtensionPolicy(req, issuer);

        CertificateTemplate template = new CertificateTemplate();
        template.setName(req.name());
        template.setIssuer(issuer);
        template.setCnRegex(req.cnRegex());
        template.setSanRegex(req.sanRegex());
        template.setTtlDays(req.ttlDays());
        template.setKeyUsage(req.keyUsage());
        template.setExtendedKeyUsage(req.extendedKeyUsage());

        CertificateTemplate saved = templateRepository.save(template);
        
        logger.info("Successfully created certificate template id={} with name='{}' for issuerId={}",
                saved.getId(), saved.getName(), issuer.getId());

        return toResponse(saved);
    }

    public List<CertificateTemplateResponse> getByIssuer(Long issuerId) {
        return templateRepository.findByIssuerId(issuerId).stream()
                .map(this::toResponse)
                .toList();
    }

    private CertificateTemplateResponse toResponse(CertificateTemplate t) {
        return new CertificateTemplateResponse(
                t.getId(),
                t.getName(),
                t.getIssuer().getId(),
                t.getIssuer().getSubjectCommonName(),
                t.getCnRegex(),
                t.getSanRegex(),
                t.getTtlDays(),
                t.getKeyUsage(),
                t.getExtendedKeyUsage()
        );
    }

    private void validateExtensionPolicy(CertificateTemplateRequest request, Certificate issuerEntity) {
        try {
            // 1. Učitaj X509 sertifikat issuera iz njegovog keystore-a
            X509Certificate issuerCert = loadX509Certificate(issuerEntity);

            // 2. Izvuci sve dozvoljene ekstenzije koje issuer ima
            Set<String> issuerAllowedExtensions = new HashSet<>();
            boolean[] ku = issuerCert.getKeyUsage();
            if (ku != null) {
                if (ku[0]) issuerAllowedExtensions.add("digitalSignature");
                if (ku[1]) issuerAllowedExtensions.add("nonRepudiation");
                if (ku[2]) issuerAllowedExtensions.add("keyEncipherment");
                if (ku[3]) issuerAllowedExtensions.add("dataEncipherment");
                // Ne dodajemo keyCertSign i cRLSign jer se one ne nasljeđuju na isti način
            }
            List<String> ekuOids = issuerCert.getExtendedKeyUsage();
            if (ekuOids != null) {
                for (String oid : ekuOids) {
                    if (oid.equals("1.3.6.1.5.5.7.3.1")) issuerAllowedExtensions.add("serverAuth");
                    if (oid.equals("1.3.6.1.5.5.7.3.2")) issuerAllowedExtensions.add("clientAuth");
                    if (oid.equals("1.3.6.1.5.5.7.3.3")) issuerAllowedExtensions.add("codeSigning");
                    if (oid.equals("1.3.6.1.5.5.7.3.4")) issuerAllowedExtensions.add("emailProtection");
                }
            }

            Set<String> requestedExtensions = new HashSet<>();
            if (request.keyUsage() != null && !request.keyUsage().isEmpty()) {
                requestedExtensions.addAll(Arrays.asList(request.keyUsage().split(",")));
            }
            if (request.extendedKeyUsage() != null && !request.extendedKeyUsage().isEmpty()) {
                requestedExtensions.addAll(Arrays.asList(request.extendedKeyUsage().split(",")));
            }

            // 4. Proveri da li je skup traženih ekstenzija podskup dozvoljenih
            if (!issuerAllowedExtensions.containsAll(requestedExtensions)) {
                requestedExtensions.removeAll(issuerAllowedExtensions);
                throw new RuntimeException("Template defines extensions not permitted by the issuer. Forbidden extensions: " + requestedExtensions);
            }

        } catch (Exception e) {
            throw new RuntimeException("Failed to validate certificate policy: " + e.getMessage(), e);
        }
    }

    private X509Certificate loadX509Certificate(Certificate issuerEntity) throws Exception {
        /*String plainPassword = encryptionService.decrypt(
                issuerEntity.getKeyStorePassword(),
                issuerEntity.getOwner().getSymmetricKey()
        );*/

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

        X509Certificate issuerCert = (X509Certificate) ks.getCertificate(issuerEntity.getSerialNumber());
        if (issuerCert == null) {
            throw new RuntimeException("Issuer certificate not found in keystore with alias: " + issuerEntity.getSerialNumber());
        }
        return issuerCert;
    }
}
