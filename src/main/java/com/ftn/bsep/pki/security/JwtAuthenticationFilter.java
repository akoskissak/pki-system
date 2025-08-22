package com.ftn.bsep.pki.security;

import com.ftn.bsep.pki.service.JwtService;
import com.ftn.bsep.pki.session.SessionManager;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;
    private final CustomUserDetailsService customUserDetailsService;
    private final SessionManager sessionManager;

    public JwtAuthenticationFilter(final JwtService jwtService, final UserDetailsService userDetailsService, CustomUserDetailsService customUserDetailsService, SessionManager sessionManager) {
        this.jwtService = jwtService;
        this.userDetailsService = userDetailsService;
        this.customUserDetailsService = customUserDetailsService;
        this.sessionManager = sessionManager;
    }
    
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);
            if (jwtService.validateToken(token)) {
                
                String tokenId = jwtService.getTokenClaims(token).getId();
                if(sessionManager.getSessions().containsKey(tokenId)) {
                    String email = jwtService.getEmailFromToken(token);
                    UserDetails userDetails = customUserDetailsService.loadUserByUsername(email);

                    UsernamePasswordAuthenticationToken authentication =
                            new UsernamePasswordAuthenticationToken(
                                    userDetails, token, userDetails.getAuthorities());

                    SecurityContextHolder.getContext().setAuthentication(authentication);
                } else {
                    SecurityContextHolder.clearContext();
                    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Token revoked");
                    return;
                }

            }
        }

        filterChain.doFilter(request, response);
    }
}
