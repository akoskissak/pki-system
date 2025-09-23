package com.ftn.bsep.pki.dto;

import java.util.List;

public record SelfSignedRequest(
        String commonName,
        String surname,
        String givenname,
        String organization,
        String organizationalUnit,
        String country,
        Long ownerId,
        int validityDays,
        List<String> extensions,
        List<SanDto> subjectAlternativeNames
) {}
