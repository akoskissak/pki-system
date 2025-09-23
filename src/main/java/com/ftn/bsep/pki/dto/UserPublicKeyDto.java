package com.ftn.bsep.pki.dto;

public class UserPublicKeyDto {
    private Long id;
    private String publicKey;

    public UserPublicKeyDto(Long id, String publicKey) {
        this.id = id;
        this.publicKey = publicKey;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }
}
