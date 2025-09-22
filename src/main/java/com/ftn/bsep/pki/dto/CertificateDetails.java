package com.ftn.bsep.pki.dto;

import java.util.List;

public record CertificateDetails(
        boolean isCa,
        Integer pathLength,
        List<String> keyUsage
) { }
