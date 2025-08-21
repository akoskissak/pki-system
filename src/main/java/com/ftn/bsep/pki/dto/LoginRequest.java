package com.ftn.bsep.pki.dto;

import lombok.Data;

@Data
public class LoginRequest {
    private String email;
    private String password;
    private String recaptcha;
}
