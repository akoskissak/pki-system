package com.ftn.bsep.pki.controller;

import com.ftn.bsep.pki.dto.PasswordDto;
import com.ftn.bsep.pki.entity.Password;
import com.ftn.bsep.pki.entity.User;
import com.ftn.bsep.pki.repository.IUserRepository;
import com.ftn.bsep.pki.service.PasswordService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;
import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/api/passwords")
public class PasswordController {
    private final PasswordService passwordService;
    private final IUserRepository userRepository;

    public PasswordController(PasswordService passwordService, IUserRepository userRepository) {
        this.passwordService = passwordService;
        this.userRepository = userRepository;
    }

    private Optional<User> getLoggedInUser(Principal principal) {
        return userRepository.findByEmail(principal.getName());
    }

    @PostMapping
    @PreAuthorize("hasAuthority('END_USER')")
    public ResponseEntity<Password> savePassword(@RequestBody PasswordDto passwordDto, Principal principal) {
        User owner = getLoggedInUser(principal).orElseThrow(() -> new RuntimeException("User not found"));

        Password savedPassword = passwordService.savePassword(
                passwordDto.getSiteName(),
                passwordDto.getUsername(),
                passwordDto.getEncryptedPassword(),
                owner
        );
        return ResponseEntity.ok(savedPassword);
    }

    @GetMapping
    @PreAuthorize("hasAuthority('END_USER')")
    public ResponseEntity<List<Password>> getMyPasswords(Principal principal) {
        User user = getLoggedInUser(principal).orElseThrow(() -> new RuntimeException("User not found"));

        List<Password> passwords = passwordService.getPasswordsForUser(user.getId());
        return ResponseEntity.ok(passwords);
    }
}
