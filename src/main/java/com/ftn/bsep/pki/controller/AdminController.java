package com.ftn.bsep.pki.controller;

import com.ftn.bsep.pki.dto.ApiResponse;
import com.ftn.bsep.pki.dto.CreateCAUserRequest;
import com.ftn.bsep.pki.entity.User;
import com.ftn.bsep.pki.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/admin")
public class AdminController {
    private final UserService userService;
    
    @Autowired
    public AdminController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("/create-ca-user")
    @PreAuthorize("hasAuthority('ADMIN')")
    public ResponseEntity<ApiResponse> createCaUser(@RequestBody CreateCAUserRequest request) {
        try {
            userService.createCAUser(request);
            return ResponseEntity.ok(ApiResponse.success("CA user successfully created with temporary password"));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(ApiResponse.failure("Error creating CA user: " + e.getMessage()));
        }
    }
}
