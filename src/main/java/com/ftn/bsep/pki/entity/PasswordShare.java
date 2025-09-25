package com.ftn.bsep.pki.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import jakarta.persistence.Lob;
import jakarta.persistence.PrePersist;
import lombok.Getter;
import lombok.Setter;

import java.time.Instant;

@Embeddable
@Getter
@Setter
public class PasswordShare {
    @Column(name = "user_id")
    private Long userId;

    @Lob
    private String encryptedPassword;

    @Column(name = "shared_at")
    private Instant sharedAt;

    @Column(name = "shared_by_user_id")
    private Long sharedByUserId;
}
