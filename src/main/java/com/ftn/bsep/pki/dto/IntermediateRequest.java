package com.ftn.bsep.pki.dto;

import java.util.List;

public record IntermediateRequest(
        Long issuerId,
        Long issuerOwnerId,
        String commonName,
        String organization,
        String organizationalUnit,
        String country,
        int validityDays,
        List<String> extensions
) {}
