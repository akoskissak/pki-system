package com.ftn.bsep.pki.service;
 
import com.ftn.bsep.pki.entity.Role;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.UUID;

@Service
public class JwtService {
    
    @Value("${jwt.secret}")
    private String secret;
    
    @Value("${jwt.expiration}")
    private long expiration;
    
    public String generateToken(String email, Role role, Long userId) {
        String tokenId = UUID.randomUUID().toString();
        
        return Jwts.builder()
                .setId(tokenId)
                .setSubject(email)
                .claim("role", role.getName())
                .claim("id", userId)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8)), SignatureAlgorithm.HS256)
                .compact();
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
}
