package com.ftn.bsep.pki.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class LoginData {
    private String token;
    private Boolean requires2FA;
    private String tempToken;
}
