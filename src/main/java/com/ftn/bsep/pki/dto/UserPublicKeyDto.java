package com.ftn.bsep.pki.dto;

public class UserPublicKeyDto {
    private Long id;
    private String publicKey;
    private String email;

    public UserPublicKeyDto(Long id, String publicKey,  String email) {
        this.id = id;
        this.publicKey = publicKey;
        this.email = email;
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

    public String getEmail() { return email; }

    public void setEmail(String email) { this.email = email; }
}
