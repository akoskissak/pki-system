package com.ftn.bsep.pki.dto;

import lombok.Getter;

@Getter
public class AuthResult {
    private boolean success;
    private String message;

    public AuthResult(boolean success, String message) {
        this.success = success;
        this.message = message;
    }
    
}
