package com.ftn.bsep.pki.dto;

import java.time.Instant;

public class SharedPasswordDtoResponse {
    private Long targetUserId;
    private String encryptedPasswordForTargetUser;
    private Instant sharedAt;
    private Long ownerId;
    private String targetUserEmail;

    public SharedPasswordDtoResponse(Long targetUserId, String encryptedPasswordForTargetUser, Instant sharedAt, Long ownerId, String targetUserEmail) {
        this.targetUserId = targetUserId;
        this.encryptedPasswordForTargetUser = encryptedPasswordForTargetUser;
        this.sharedAt = sharedAt;
        this.ownerId = ownerId;
        this.targetUserEmail = targetUserEmail;
    }

    public SharedPasswordDtoResponse() {

    }

    public Long getTargetUserId() {
        return targetUserId;
    }

    public void setTargetUserId(Long targetUserId) {
        this.targetUserId = targetUserId;
    }

    public String getEncryptedPasswordForTargetUser() {
        return encryptedPasswordForTargetUser;
    }

    public void setEncryptedPasswordForTargetUser(String encryptedPasswordForTargetUser) {
        this.encryptedPasswordForTargetUser = encryptedPasswordForTargetUser;
    }

    public Instant getSharedAt() {
        return sharedAt;
    }

    public void setSharedAt(Instant sharedAt) {
        this.sharedAt = sharedAt;
    }

    public Long getOwnerId() {
        return ownerId;
    }

    public void setOwnerId(Long ownerId) {
        this.ownerId = ownerId;
    }

    public String getTargetUserEmail() {
        return targetUserEmail;
    }

    public void setTargetUserEmail(String targetUserEmail) {
        this.targetUserEmail = targetUserEmail;
    }

}
