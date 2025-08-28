package com.ftn.bsep.pki.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.time.Instant;

@Entity
@Getter
@Setter
@Table(name = "pending_csrs")
public class PendingCsrRequest {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "csr_content", columnDefinition = "TEXT")
    private String csrContent;

    @Column(name = "common_name")
    private String commonName;

    @Column(name = "submitted_at")
    private Instant submittedAt;
}
