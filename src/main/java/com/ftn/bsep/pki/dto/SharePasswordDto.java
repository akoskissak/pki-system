package com.ftn.bsep.pki.dto;

public class SharePasswordDto {
    private Long targetUserId;
    private String encryptedPasswordForTargetUser;

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
}
