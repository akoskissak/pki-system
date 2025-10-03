package com.ftn.bsep.pki.dto;

public record CertificateTemplateResponse(
        Long id,
        String name,
        Long issuerId,
        String issuerCommonName,
        String cnRegex,
        String sanRegex,
        Integer ttlDays,
        String keyUsage,
        String extendedKeyUsage
) {
}
