package com.ftn.bsep.pki.dto;

import java.time.Instant;

public class SharedWithMePasswordDto {
    private Long id;
    private String siteName;
    private String username;
    private String encryptedPasswordForTargetUser;
    private String ownerId;
    private String ownerEmail;
    private Instant sharedAt;

    public SharedWithMePasswordDto(Long id, String siteName, String username, String ownerId, String ownerEmail, Instant sharedAt, String encryptedPasswordForTargetUser) {
        this.id = id;
        this.siteName = siteName;
        this.username = username;
        this.ownerId = ownerId;
        this.ownerEmail = ownerEmail;
        this.sharedAt = sharedAt;
        this.encryptedPasswordForTargetUser = encryptedPasswordForTargetUser;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getSiteName() {
        return siteName;
    }

    public void setSiteName(String siteName) {
        this.siteName = siteName;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getOwnerId() {
        return ownerId;
    }

    public void setOwnerId(String ownerId) {
        this.ownerId = ownerId;
    }

    public String getOwnerEmail() {
        return ownerEmail;
    }

    public void setOwnerEmail(String ownerEmail) {
        this.ownerEmail = ownerEmail;
    }

    public Instant getSharedAt() {
        return sharedAt;
    }

    public void setSharedAt(Instant sharedAt) {
        this.sharedAt = sharedAt;
    }

    public String getEncryptedPasswordForTargetUser() {
        return encryptedPasswordForTargetUser;
    }

    public void setEncryptedPasswordForTargetUser(String encryptedPasswordForTargetUser) {
        this.encryptedPasswordForTargetUser = encryptedPasswordForTargetUser;
    }
}


