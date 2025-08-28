package com.ftn.bsep.pki.controller;

import com.ftn.bsep.pki.dto.*;
import com.ftn.bsep.pki.service.CertificateService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

@RestController
@RequestMapping("/api/certificates")
public class CertificateController {
    private final CertificateService service;

    public CertificateController(CertificateService service) {
        this.service = service;
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
                        certEntity.getSerialNumber(),
                        certEntity.getSubjectCommonName(),
                        certEntity.getIssuerCommonName(),
                        certEntity.getKeyStorePath()
                )
        );
    }

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
