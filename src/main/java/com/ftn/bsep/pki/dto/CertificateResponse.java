package com.ftn.bsep.pki.dto;

import java.time.Instant;

public record CertificateResponse(
        Long id,
        String serialNumber,
        String subjectCN,
        String issuerCN,
        String path,
        Instant notAfter,
        Long ownerId,
        String type,
        CertificateDetails details ) {

}
