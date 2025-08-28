package com.ftn.bsep.pki.controller;

import com.ftn.bsep.pki.dto.CertificateResponse;
import com.ftn.bsep.pki.dto.IntermediateRequest;
import com.ftn.bsep.pki.dto.SelfSignedRequest;
import com.ftn.bsep.pki.dto.SelfSignedResponse;
import com.ftn.bsep.pki.service.CertificateService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

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
    public ResponseEntity<String> submitCsr(@RequestParam("file") MultipartFile file) throws Exception {
        if (file.isEmpty()) {
            return ResponseEntity.badRequest().body("CSR file is empty.");
        }

        service.handlePendingCsr(file);

        return ResponseEntity.ok("CSR submitted successfully. Awaiting approval.");
    }
}
