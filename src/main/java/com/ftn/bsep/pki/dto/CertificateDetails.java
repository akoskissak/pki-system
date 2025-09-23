package com.ftn.bsep.pki.dto;

import java.util.List;
import java.util.Map;

public record CertificateDetails(
        boolean isCa,
        Integer pathLength,
        List<String> keyUsage,
        List<String> extendedKeyUsage,
        Map<String, List<String>> subjectAlternativeNames
) { }
