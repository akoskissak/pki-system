package com.ftn.bsep.pki.dto;

public record IntermediateResponse(
        String serialNumber,
        String subjectCN,
        String issuerCN,
        String path,
        int validityDays
) {}