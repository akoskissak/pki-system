package com.ftn.bsep.pki.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

@Entity
@Getter
@Setter
@Table(name = "certificate_templates")
public class CertificateTemplate {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String name;   // Naziv šablona

    @ManyToOne
    @JoinColumn(name = "issuer_id", nullable = false)
    private Certificate issuer;   // CA issuer sertifikat

    @Column(nullable = false)
    private String cnRegex;   // regex za CN

    @Column(length = 1024)
    private String sanRegex;  // regex za SAN

    @Column(nullable = false)
    private Integer ttlDays;  // maksimalno trajanje

    @Column(nullable = true)
    private String keyUsage;  // npr. "digitalSignature,keyEncipherment"

    @Column(nullable = true)
    private String extendedKeyUsage; // npr. "serverAuth,clientAuth"
}
