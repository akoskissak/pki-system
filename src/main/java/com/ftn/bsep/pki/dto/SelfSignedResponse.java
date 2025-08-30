package com.ftn.bsep.pki.dto;

public record SelfSignedResponse(
        String subjectDn,
        String filePath
) {}
