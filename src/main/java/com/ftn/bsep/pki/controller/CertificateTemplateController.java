package com.ftn.bsep.pki.controller;

import com.ftn.bsep.pki.dto.CertificateTemplateRequest;
import com.ftn.bsep.pki.dto.CertificateTemplateResponse;
import com.ftn.bsep.pki.service.CertificateTemplateService;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/templates")

public class CertificateTemplateController {
    private final CertificateTemplateService service;

    public CertificateTemplateController(CertificateTemplateService service) {
        this.service = service;
    }

    @PostMapping
    public CertificateTemplateResponse createTemplate(@RequestBody CertificateTemplateRequest req) {
        return service.create(req);
    }

    @GetMapping("/issuer/{issuerId}")
    public List<CertificateTemplateResponse> getTemplatesForIssuer(@PathVariable Long issuerId) {
        return service.getByIssuer(issuerId);
    }
}
