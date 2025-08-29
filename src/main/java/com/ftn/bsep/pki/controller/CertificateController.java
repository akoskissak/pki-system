package com.ftn.bsep.pki.controller;


import com.ftn.bsep.pki.dto.CertificateResponse;
import com.ftn.bsep.pki.dto.IntermediateRequest;
import com.ftn.bsep.pki.dto.SelfSignedRequest;
import com.ftn.bsep.pki.dto.SelfSignedResponse;
import com.ftn.bsep.pki.entity.User;
import com.ftn.bsep.pki.repository.IUserRepository;
import com.ftn.bsep.pki.dto.*;
import com.ftn.bsep.pki.service.CertificateService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

import java.util.List;
import java.util.stream.Collectors;

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


    @GetMapping
    @PreAuthorize("hasRole('ROLE_ADMIN') or hasRole('ROLE_CA_USER')")
    public ResponseEntity<List<CertificateResponse>> getCertificates(Authentication auth) {
        String email = auth.getName();
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        var certEntities = service.getCertificatesForUser(user);
        var certResponses = certEntities.stream()
                .map(c -> new CertificateResponse(
                        c.getId(),
                        c.getSerialNumber(),
                        c.getSubjectCommonName(),
                        c.getIssuerCommonName(),
                        c.getKeyStorePath(),
                        c.getNotAfter(),
                        c.getOwner() != null ? c.getOwner().getId() : null,
                        c.getType().name()
                ))
                .toList();

        return ResponseEntity.ok(certResponses);

    @PostMapping("/csr")
    @PreAuthorize("hasRole('ROLE_CA_USER') or hasRole('ROLE_ADMIN')")
    public ResponseEntity<CertificateResponse> issueFromCsr(
            @RequestParam("file") MultipartFile file,
            @RequestParam("issuerId") Long issuerId,
            @RequestParam("issuerOwnerId") Long issuerOwnerId,
            @RequestParam("validityDays") int validityDays
    ) throws Exception {

        if (file.isEmpty()) {
            throw new IllegalArgumentException("CSR file is empty.");
        }

        var certEntity = service.issueFromCsr(file, issuerId, issuerOwnerId, validityDays);

        return ResponseEntity.ok(
                new CertificateResponse(
                        certEntity.getSerialNumber(),
                        certEntity.getSubjectCommonName(),
                        certEntity.getIssuerCommonName(),
                        certEntity.getKeyStorePath()
                )
        );
    }

    @PostMapping("/submit-csr")
    @PreAuthorize("hasRole('ROLE_END_USER')")
    public ResponseEntity<String> submitCsr(
            @RequestParam("file") MultipartFile file,
            @RequestParam("issuerId") String issuerId,
            @RequestParam("validityDays") Integer validityDays
    ) throws Exception {
        if (file.isEmpty()) {
            return ResponseEntity.badRequest().body("CSR file is empty.");
        }

        // Prosleđivanje novih parametara servisu
        service.handlePendingCsr(file, issuerId, validityDays);

        return ResponseEntity.ok("CSR submitted successfully. Awaiting approval.");
    }

    @GetMapping("/ca-certs")
    @PreAuthorize("hasRole('ROLE_END_USER')")
    public ResponseEntity<List<IntermediateResponse>> getCAs() {
        var caList = service.getAllCAs();
        return ResponseEntity.ok(caList);

    }
}
