package com.ftn.bsep.pki.controller;

import com.ftn.bsep.pki.dto.*;
import com.ftn.bsep.pki.service.JwtService;
import com.ftn.bsep.pki.service.PasswordResetService;
import com.ftn.bsep.pki.service.RecaptchaService;
import com.ftn.bsep.pki.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

  private final UserService userService;
  private final RecaptchaService recaptchaService;
  private final JwtService jwtService;
  private final PasswordResetService passwordResetService;

  @Autowired
  public AuthController(UserService userService, RecaptchaService recaptchaService, JwtService jwtService, PasswordResetService passwordResetService) {
    this.userService = userService;
    this.recaptchaService = recaptchaService;
    this.jwtService = jwtService;
    this.passwordResetService = passwordResetService;
  }

  @PostMapping("/register")
  public ResponseEntity<ApiResponse> register(@RequestBody RegisterRequest request){
    ApiResponse response = userService.register(request);
    if(response.getError() != null) {
      return ResponseEntity.badRequest().body(response);
    } else {
      return ResponseEntity.ok(response);
    }
  }

  @GetMapping("/activate")
  public ResponseEntity<ApiResponse> activate(@RequestParam String token){
    ApiResponse response = userService.activateAccount(token);
    if(response.getError() != null) {
      return ResponseEntity.badRequest().body(response);
    } else {
      return ResponseEntity.ok(response);
    }
  }
  
  @PostMapping("/login")
  public ResponseEntity<ApiResponse> login(@RequestBody LoginRequest request) {
    if (!recaptchaService.verify(request.getRecaptcha())) {
      return ResponseEntity.badRequest().body(ApiResponse.failure("CAPTCHA verification failed"));
    }
    
    AuthResult authenticated = userService.authenticate(request.getEmail(), request.getPassword());
    if(!authenticated.isSuccess()) {
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
              .body(ApiResponse.failure(authenticated.getMessage()));
    }
    
    String token = jwtService.generateToken(request.getEmail());
    return ResponseEntity.ok(ApiResponse.successWithData("Successful login", token));
  }
  
  @PostMapping("/forgot-password")
  public ResponseEntity<AuthResult> forgotPassword(@RequestBody ForgotPasswordRequest request) {
    AuthResult result = passwordResetService.createPasswordResetToken(request.getEmail());
    if(!result.isSuccess()) {
      return ResponseEntity.badRequest().body(result);
    }
    return ResponseEntity.ok(result);
  }
  
  @PostMapping("/reset-password")
  public ResponseEntity<ApiResponse> resetPassword(@RequestBody ResetPasswordRequest request) {
    ApiResponse response = passwordResetService.resetPassword(request);
    if(response.getError() != null) {
      return ResponseEntity.badRequest().body(response);
    } else {
      return ResponseEntity.ok(response);
    }
  }
}
