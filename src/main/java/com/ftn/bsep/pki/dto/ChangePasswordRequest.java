package com.ftn.bsep.pki.dto;

import lombok.Data;

@Data
public class ChangePasswordRequest {
    String newPassword;
    String confirmPassword;
}
