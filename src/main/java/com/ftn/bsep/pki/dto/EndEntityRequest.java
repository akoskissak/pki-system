package com.ftn.bsep.pki.dto;

import java.util.List;

public record EndEntityRequest(
        Long issuerId,
        Long issuerOwnerId,
        String publicKey, // JAVNI KLJUČ END-ENTITY KORISNIKA
        String commonName,
        String surname,
        String givenname,
        String organization,
        String organizationalUnit,
        String country,
        int validityDays,
        List<String> extensions,
        List<SanDto> subjectAlternativeNames) {}
