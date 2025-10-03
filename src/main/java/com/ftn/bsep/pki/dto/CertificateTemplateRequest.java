package com.ftn.bsep.pki.dto;

public record CertificateTemplateRequest(
        String name,
        Long issuerId,
        String cnRegex,
        String sanRegex,
        Integer ttlDays,
        String keyUsage,
        String extendedKeyUsage) { }
