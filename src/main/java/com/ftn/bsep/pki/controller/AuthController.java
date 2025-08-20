package com.ftn.bsep.pki.controller;

import com.ftn.bsep.pki.dto.ApiResponse;
import com.ftn.bsep.pki.dto.RegisterRequest;
import com.ftn.bsep.pki.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

  private final UserService userService;

  @Autowired
  public AuthController(UserService userService) {
    this.userService = userService;
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
}
