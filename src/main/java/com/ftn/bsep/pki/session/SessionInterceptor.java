package com.ftn.bsep.pki.session;

import com.ftn.bsep.pki.service.JwtService;
import io.jsonwebtoken.Claims;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

@Component
public class SessionInterceptor implements HandlerInterceptor {
    private final SessionManager sessionManager;
    private final JwtService jwtService;

    public SessionInterceptor(SessionManager sessionManager, JwtService jwtService) {
        this.sessionManager = sessionManager;
        this.jwtService = jwtService;
    }
    
    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response,  Object handler) {
        String authHeader = request.getHeader("Authorization");
        
        if(authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7); // preskocimo 7 zbog Bearer
            
            try {
                Claims claims = jwtService.getTokenClaims(token);
                String tokenId = claims.getId();
                if(tokenId != null) {
                    sessionManager.updateLastActivity(tokenId);
                }
            } catch (Exception e) {
                System.out.println("Not valid JWT token: " + e.getMessage());
            }
        }
        
        return true;
    }
}
