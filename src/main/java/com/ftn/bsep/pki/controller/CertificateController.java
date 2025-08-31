package com.ftn.bsep.pki.controller;


import com.ftn.bsep.pki.config.KeyStoreConfig;
import com.ftn.bsep.pki.dto.CertificateResponse;
import com.ftn.bsep.pki.dto.IntermediateRequest;
import com.ftn.bsep.pki.dto.SelfSignedRequest;
import com.ftn.bsep.pki.dto.SelfSignedResponse;
import com.ftn.bsep.pki.entity.User;
import com.ftn.bsep.pki.repository.IUserRepository;
import com.ftn.bsep.pki.dto.*;
import com.ftn.bsep.pki.service.CertificateService;
import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Principal;
import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/certificates")
public class CertificateController {
    private final CertificateService service;
    private final IUserRepository userRepository;
    private final KeyStoreConfig cfg;
    private final String certificateStoragePath;

    public CertificateController(CertificateService service, IUserRepository userRepository, KeyStoreConfig keyStoreConfig) {
        this.service = service;
        this.userRepository = userRepository;
        this.cfg = keyStoreConfig;
        this.certificateStoragePath = Paths.get(cfg.getEeDir()).toString();

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
    @PreAuthorize("hasRole('ROLE_ADMIN') or hasRole('ROLE_CA_USER') or hasRole('ROLE_END_USER')")
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
    }

    @PostMapping("/handle-csr/{id}")
    @PreAuthorize("hasRole('ROLE_CA_USER') or hasRole('ROLE_ADMIN')")
    public ResponseEntity<CertificateResponse> issueFromPendingCsr(
            @PathVariable("id") Long id
    ) throws Exception {
        var certEntity = service.issueFromPendingCsr(id);

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
        String email = principal.getName();

        User owner = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("Logged-in user not found."));
        Long ownerId = owner.getId();

        if (file.isEmpty()) {
            return ResponseEntity.badRequest().body("CSR file is empty.");
        }

        service.handlePendingCsr(file, issuerId, validityDays, ownerId);

        return ResponseEntity.ok("CSR submitted successfully. Awaiting approval.");
    }

    @GetMapping("/ca-certs")
    @PreAuthorize("hasRole('ROLE_END_USER')")
    public ResponseEntity<List<IntermediateResponse>> getCAs() {
        var caList = service.getAllCAs();
        return ResponseEntity.ok(caList);
    }

    @GetMapping("/pending-requests")
    @PreAuthorize("hasRole('ROLE_CA_USER') or hasRole('ROLE_ADMIN')")
    public ResponseEntity<List<PendingCsrResponse>> getPendingRequests(Principal principal) {
        // Get the logged-in user's ID
        User loggedInUser = userRepository.findByEmail(principal.getName())
                .orElseThrow(() -> new UsernameNotFoundException("User not found."));

        List<PendingCsrResponse> pendingRequests = service.getPendingCsrRequestsForUser(loggedInUser.getId());

        return ResponseEntity.ok(pendingRequests);
    }

    @GetMapping("/{serialNumber}/download")
    @PreAuthorize("hasRole('ROLE_END_USER')")
    public ResponseEntity<Resource> downloadCertificate(@PathVariable String serialNumber) {
        try {
            Path filePath = Paths.get(certificateStoragePath).resolve(serialNumber + ".cer").normalize();
            Resource resource = new UrlResource(filePath.toUri());

            if (resource.exists() && resource.isReadable()) {
                String contentType = "application/pkix-cert";
                String headerValue = "attachment; filename=\"" + resource.getFilename() + "\"";

                return ResponseEntity.ok()
                        .contentType(MediaType.parseMediaType(contentType))
                        .header(HttpHeaders.CONTENT_DISPOSITION, headerValue)
                        .body(resource);
            } else {
                return ResponseEntity.notFound().build();
            }
        } catch (IOException ex) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }
}
