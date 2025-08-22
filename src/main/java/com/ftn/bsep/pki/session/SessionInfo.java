package com.ftn.bsep.pki.session;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class SessionInfo {
    private String tokenId;
    private String email;
    private String ipAddress;
    private String userAgent;
    private LocalDateTime issuedAt;
    private LocalDateTime lastActivity;
    private Boolean currentSession;
}
