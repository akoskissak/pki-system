package com.ftn.bsep.pki.controller;

import com.ftn.bsep.pki.service.JwtService;
import com.ftn.bsep.pki.session.SessionInfo;
import com.ftn.bsep.pki.session.SessionManager;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/user/sessions")
public class SessionController {
    private final SessionManager sessionManager;
    private final JwtService jwtService;

    public SessionController(SessionManager sessionManager, JwtService jwtService) {
        this.sessionManager = sessionManager;
        this.jwtService = jwtService;
    }
    
    @GetMapping
    @PreAuthorize("hasAuthority('END_USER')")
    public List<SessionInfo> getSessions(Authentication auth) {
        String email = auth.getName();
        String token = (String) auth.getCredentials();
        return sessionManager.getUserSessions(email, jwtService.getTokenClaims(token).getId());
    }
    
    @PostMapping("/logout")
    @PreAuthorize("hasAuthority('END_USER')")
    public void logoutSession(@RequestBody Map<String, String> body) {
        String tokenId = body.get("tokenId");
        sessionManager.removeSession(tokenId);
    }
    
    @PostMapping("/logoutAllOthers")
    @PreAuthorize("hasAuthoristhy('END_USER')")
    public void logoutAllOtherSessions(Authentication auth) {
        String email = auth.getName();
        String token = (String) auth.getCredentials();
        String currentTokenId = jwtService.getTokenClaims(token).getId();   
        List<SessionInfo> sessions = sessionManager.getUserSessions(email, currentTokenId);
        
        sessions.stream()
                .filter(s -> !s.getCurrentSession())
                .forEach(s -> sessionManager.removeSession(s.getTokenId()));
    }
}
