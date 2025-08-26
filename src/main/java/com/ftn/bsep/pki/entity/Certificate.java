package com.ftn.bsep.pki.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.time.Instant;

@Entity
@Getter
@Setter
@Table(name = "certificates")
public class Certificate {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String serialNumber;

    @Column(nullable = false)
    private String subjectCommonName;

    @Column(nullable = false)
    private String subjectSurname;

    @Column(nullable = false)
    private String subjectGivenname;

    @Column(nullable = false)
    private String subjectOrganization;

    @Column(nullable = false)
    private String subjectOrganizationalUnit;

    @Column(nullable = false)
    private String subjectCountry;

    @Column(nullable = false)
    private String issuerCommonName;

    @Column(nullable = false)
    private String issuerOrganization;

    @Column(nullable = false)
    private Instant notBefore;

    @Column(nullable = false)
    private Instant notAfter;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private CertificateType type;

    @ManyToOne
    @JoinColumn(name = "parent_certificate_id")
    private Certificate parentCertificate;

    @Column(nullable = false)
    private boolean isRevoked;

    @Column(nullable = false)
    private String keyStorePath;

    @Column(nullable = false)
    private String keyStorePassword;
}
