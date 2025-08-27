package com.ftn.bsep.pki.dto;

public record CertificateResponse(
        String serialNumber,
        String subjectCN,
        String issuerCN,
        String path
) {}
