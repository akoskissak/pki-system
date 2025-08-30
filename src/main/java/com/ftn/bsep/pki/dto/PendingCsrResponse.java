package com.ftn.bsep.pki.dto;

import java.time.Instant;

public record PendingCsrResponse(
        Long id,
        String commonName,
        Instant submittedAt,
        String issuerSerialNumber,
        Integer validityDays
) {}
