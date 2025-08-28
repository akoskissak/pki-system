package com.ftn.bsep.pki.controller;

import com.ftn.bsep.pki.dto.ApiResponse;
import com.ftn.bsep.pki.dto.ChangePasswordRequest;
import com.ftn.bsep.pki.service.UserService;
import io.jsonwebtoken.Jwt;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/ca")
public class CAUserController {
    private final UserService userService;

    @Autowired
    public CAUserController(UserService userService) {
        this.userService = userService;
    }
    
    // change password za CA USER prilikom prvog login-a
    @PostMapping("/change-password")
    @PreAuthorize("hasAuthority('CA_USER')")
    public ResponseEntity<ApiResponse> changePassword(@RequestBody ChangePasswordRequest request, Authentication auth) {

        String email = auth.getName();
        ApiResponse response = userService.changePasswordForCAUser(email, request);

        if (response.getError() != null) {
            return ResponseEntity.badRequest().body(response);
        } else {
            return ResponseEntity.ok(response);
        }
    }
}
