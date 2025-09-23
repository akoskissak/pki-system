package com.ftn.bsep.pki.controller;

import com.ftn.bsep.pki.dto.RevokeRequest;
import com.ftn.bsep.pki.entity.User;
import com.ftn.bsep.pki.repository.IUserRepository;
import com.ftn.bsep.pki.service.CertificateService;
import com.ftn.bsep.pki.service.RevocationService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;
import java.time.Instant;
import java.util.Map;

@RestController
@RequestMapping("/api/revocation")
public class RevocationController {
    private final RevocationService revocationService;
    private final IUserRepository userRepository;

    public RevocationController(RevocationService revocationService, IUserRepository userRepository) {
        this.revocationService = revocationService;
        this.userRepository = userRepository;
    }

    @PostMapping("/revoke/{certId}")
    @PreAuthorize("hasRole('ROLE_ADMIN') or hasRole('ROLE_CA_USER') or hasRole('ROLE_END_USER')")
    // Or any other appropriate role
    public ResponseEntity<String> revoke(@PathVariable Long certId, @RequestBody RevokeRequest body, Principal principal) {
        String email = principal.getName();

        User owner = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("Logged-in user not found."));

        try {
            // Call the service method to revoke the certificate
            revocationService.revokeCertificate(certId, body.getReason(), Instant.now(), owner.getId());

            // Return a success response
            return ResponseEntity.ok("Certificate with ID " + certId + " has been successfully revoked.");

        } catch (Exception e) {
            // Return an error response if something goes wrong
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(e.getMessage());
        }
    }
}