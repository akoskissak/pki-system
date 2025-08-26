package com.ftn.bsep.pki.dto;

public record SelfSignedRequest(
        String commonName,
        String surname,
        String givenname,
        String organization,
        String organizationalUnit,
        String country,
        Long ownerId
) {}
