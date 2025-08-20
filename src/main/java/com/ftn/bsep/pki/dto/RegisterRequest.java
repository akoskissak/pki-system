package com.ftn.bsep.pki.dto;

import lombok.Data;
import lombok.Getter;
import lombok.Setter;

@Data
public class RegisterRequest {
  private String email;
  private String password;
  private String confirmPassword;
  private String firstName;
  private String lastName;
  private String organization;
}
