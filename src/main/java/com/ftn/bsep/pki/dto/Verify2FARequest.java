package com.ftn.bsep.pki.dto;

import lombok.Data;

@Data
public class Verify2FARequest {
    private String tempToken;
    private int code;
}
