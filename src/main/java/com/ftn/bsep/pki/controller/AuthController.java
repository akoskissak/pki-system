package com.ftn.bsep.pki.controller;

import com.ftn.bsep.pki.dto.*;
import com.ftn.bsep.pki.entity.User;
import com.ftn.bsep.pki.service.JwtService;
import com.ftn.bsep.pki.service.PasswordResetService;
import com.ftn.bsep.pki.service.RecaptchaService;
import com.ftn.bsep.pki.service.UserService;
import com.ftn.bsep.pki.session.SessionInfo;
import com.ftn.bsep.pki.session.SessionManager;
import io.micrometer.common.util.internal.logging.InternalLogger;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

  private final UserService userService;
  private final RecaptchaService recaptchaService;
  private final JwtService jwtService;
  private final PasswordResetService passwordResetService;
  private final SessionManager sessionManager;

  @Autowired
  public AuthController(UserService userService, RecaptchaService recaptchaService, JwtService jwtService, PasswordResetService passwordResetService, SessionManager sessionManager) {
    this.userService = userService;
    this.recaptchaService = recaptchaService;
    this.jwtService = jwtService;
    this.passwordResetService = passwordResetService;
    this.sessionManager = sessionManager;
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
  public ResponseEntity<ApiResponse> login(@RequestBody LoginRequest request, HttpServletRequest req) {
    if (!recaptchaService.verify(request.getRecaptcha())) {
      return ResponseEntity.badRequest().body(ApiResponse.failure("CAPTCHA verification failed"));
    }
    
    AuthResult authenticated = userService.authenticate(request.getEmail(), request.getPassword());
    if(!authenticated.isSuccess()) {
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
              .body(ApiResponse.failure(authenticated.getMessage()));
    }

    User user = userService.getByEmail(request.getEmail());
    
    String token = jwtService.generateToken(request.getEmail(), user.getRole());
    
    SessionInfo sessionInfo = userService.createSession(jwtService.getTokenClaims(token).getId(), request.getEmail(), req);
    sessionManager.addSession(sessionInfo);
    
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
    if (response.getError() != null) {
      return ResponseEntity.badRequest().body(response);
    } else {
      return ResponseEntity.ok(response);
    }
  }
  
  @PostMapping("/logout")
  public void logoutCurrentSession() {
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    if(authentication != null) {
      String token = (String) authentication.getCredentials();
      if (token != null) {
        sessionManager.removeSession(jwtService.getTokenClaims(token).getId());
      }
    }
  }
}
