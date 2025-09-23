package com.ftn.bsep.pki.controller;

import com.ftn.bsep.pki.dto.UserPublicKeyDto;
import com.ftn.bsep.pki.entity.User;
import com.ftn.bsep.pki.repository.IUserRepository;
import com.ftn.bsep.pki.service.CertificateService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
@RequestMapping("/api/users")
public class UserController {

    private final IUserRepository userRepository;
    private final CertificateService certificateService;

    public UserController(IUserRepository userRepository, CertificateService certificateService) {
        this.userRepository = userRepository;
        this.certificateService = certificateService;
    }

    @GetMapping("/find")
    @PreAuthorize("hasAuthority('END_USER')")
    public ResponseEntity<UserPublicKeyDto> findPublicKey(Principal principal) {
        User user = userRepository.findByEmail(principal.getName())
                .orElseThrow(() -> new UsernameNotFoundException("User not found."));
        String publicKeyPem = certificateService.getPublicKeyAsPemForUser(user);

        UserPublicKeyDto responseDto = new UserPublicKeyDto(user.getId(), publicKeyPem);
        return ResponseEntity.ok(responseDto);
    }

    @GetMapping("/me")
    @PreAuthorize("hasAuthority('END_USER')")
    public ResponseEntity<User> getLoggedInUser(Principal principal) {
        User user = userRepository.findByEmail(principal.getName())
                .orElseThrow(() -> new UsernameNotFoundException("User not found."));

        return ResponseEntity.ok(user);
    }
}
