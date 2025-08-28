package com.ftn.bsep.pki.dto;

import lombok.Data;

@Data
public class CreateCAUserRequest {
    private String email;
    private String firstName;
    private String lastName;
}
