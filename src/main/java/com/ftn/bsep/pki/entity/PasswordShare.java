package com.ftn.bsep.pki.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import lombok.Getter;
import lombok.Setter;

@Embeddable
@Getter
@Setter
public class PasswordShare {
    @Column(name = "user_id")
    private Long userId;

    private String encryptedPassword;
}
