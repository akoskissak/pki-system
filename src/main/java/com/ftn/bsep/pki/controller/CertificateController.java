package com.ftn.bsep.pki.controller;

import com.ftn.bsep.pki.dto.*;
import com.ftn.bsep.pki.entity.User;
import com.ftn.bsep.pki.repository.IUserRepository;
import com.ftn.bsep.pki.service.CertificateService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.security.Principal;
import java.util.List;

@RestController
@RequestMapping("/api/certificates")
public class CertificateController {
    private final CertificateService service;
    private final IUserRepository userRepository;

    public CertificateController(CertificateService service, IUserRepository userRepository) {
        this.service = service;
        this.userRepository = userRepository;
    }

    @PostMapping("/self-signed")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public ResponseEntity<SelfSignedResponse> selfSigned(@RequestBody SelfSignedRequest req) throws Exception {
        return ResponseEntity.ok(service.createSelfSigned(req));
    }

    @PostMapping("/intermediate")
    @PreAuthorize("hasRole('ROLE_CA_USER') or hasRole('ROLE_ADMIN')")
    public ResponseEntity<CertificateResponse> issueIntermediate(@RequestBody IntermediateRequest req) throws Exception {
        var certEntity = service.issueIntermediate(req);
        return ResponseEntity.ok(
                new CertificateResponse(
                        certEntity.getId(),
                        certEntity.getSerialNumber(),
                        certEntity.getSubjectCommonName(),
                        certEntity.getIssuerCommonName(),
                        certEntity.getKeyStorePath(),
                        certEntity.getNotAfter(),
                        certEntity.getOwner() != null ? certEntity.getOwner().getId() : null,
                        certEntity.getType().name()


                )
        );
    }

    @PostMapping("/handle-csr/{id}")
    @PreAuthorize("hasRole('ROLE_CA_USER') or hasRole('ROLE_ADMIN')")
    public ResponseEntity<CertificateResponse> issueFromPendingCsr(
            @PathVariable("id") Long id
    ) throws Exception {
        // Pozivanje servisne metode
        var certEntity = service.issueFromPendingCsr(id);

        // Vraća odgovor
        return ResponseEntity.ok(
                new CertificateResponse(
                        certEntity.getId(),
                        certEntity.getSerialNumber(),
                        certEntity.getSubjectCommonName(),
                        certEntity.getIssuerCommonName(),
                        certEntity.getKeyStorePath(),
                        certEntity.getNotAfter(),
                        certEntity.getOwner() != null ? certEntity.getOwner().getId() : null,
                        certEntity.getType().name()
                )
        );
    }

    @PostMapping("/submit-csr")
    @PreAuthorize("hasRole('ROLE_END_USER')")
    public ResponseEntity<String> submitCsr(
            @RequestParam("file") MultipartFile file,
            @RequestParam("issuerId") String issuerId,
            @RequestParam("validityDays") Integer validityDays,
            Principal principal
    ) throws Exception {
        // Dobijamo email/korisničko ime ulogovanog korisnika
        String email = principal.getName();

        // Na osnovu email-a, pronađite korisnika i njegov ID
        User owner = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("Logged-in user not found."));
        Long ownerId = owner.getId();

        if (file.isEmpty()) {
            return ResponseEntity.badRequest().body("CSR file is empty.");
        }

        // Prosleđivanje novih parametara servisu
        service.handlePendingCsr(file, issuerId, validityDays, ownerId);

        return ResponseEntity.ok("CSR submitted successfully. Awaiting approval.");
    }

    @GetMapping("/ca-certs")
    @PreAuthorize("hasRole('ROLE_END_USER')")
    public ResponseEntity<List<IntermediateResponse>> getCAs() {
        var caList = service.getAllCAs();
        return ResponseEntity.ok(caList);
    }
}
