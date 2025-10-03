package com.ftn.bsep.pki.service;
 
import com.ftn.bsep.pki.entity.Role;
import com.ftn.bsep.pki.entity.User;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.Optional;
import java.util.UUID;

@Service
public class JwtService {
    
    @Value("${jwt.secret}")
    private String secret;
    
    @Value("${jwt.expiration}")
    private long expiration;
    
    public String generateToken(String email, Role role, Long userId, boolean mustChangePassword, boolean is2FAEnabled) {
        String tokenId = UUID.randomUUID().toString();
        
        JwtBuilder builder = Jwts.builder()
                            .setId(tokenId)
                            .setSubject(email)
                            .claim("role", role.getName())
                            .claim("id", userId)
                            .claim("is2FAEnabled", is2FAEnabled)
                            .setIssuedAt(new Date())
                            .setExpiration(new Date(System.currentTimeMillis() + expiration))
                            .signWith(Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8)), SignatureAlgorithm.HS256);
        if (mustChangePassword) {
            builder.claim("mustChangePassword",  Boolean.TRUE); //kad ovdje stoji samo true javlja neku grešku
        }
        
        return builder.compact();
    }

    public String generateTempToken(User user) {
        String tokenId = UUID.randomUUID().toString();

        long tempExpiration = 5 * 60 * 1000; // 5 minuta

        JwtBuilder builder = Jwts.builder()
                .setId(tokenId)
                .setSubject(user.getEmail())
                .claim("role", user.getRole().getName())
                .claim("id", user.getId())
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + tempExpiration))
                .signWith(Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8)), SignatureAlgorithm.HS256);

        return builder.compact();
    }


    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8))).build().parseClaimsJws(token);
            return true;
        } catch (JwtException e) {
            return false;
        }
    }
    
    public Claims getTokenClaims(String token) {
        return Jwts.parserBuilder().setSigningKey(Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8))).build().parseClaimsJws(token).getBody();
    }
    
    public String getEmailFromToken(String token) {
        return getTokenClaims(token).getSubject();
    }

    public Long parseUserIdFromTempToken(String tempToken) {
        if (tempToken == null || tempToken.isEmpty()) {
            throw new RuntimeException("Temp token is missing");
        }
        
        if (!validateToken(tempToken)) {
            throw new RuntimeException("Invalid or expired temp token");
        }
        
        Claims claims = getTokenClaims(tempToken);
        
        Long userId = claims.get("id", Long.class);
        
        return userId;
    }
}
