package com.ftn.bsep.pki.controller;

import com.ftn.bsep.pki.dto.ApiResponse;
import com.ftn.bsep.pki.dto.Verify2FARequest;
import com.ftn.bsep.pki.entity.User;
import com.ftn.bsep.pki.repository.IUserRepository;
import com.ftn.bsep.pki.service.JwtService;
import com.ftn.bsep.pki.service.TwoFactorAuthService;
import com.ftn.bsep.pki.service.UserService;
import com.ftn.bsep.pki.session.SessionInfo;
import com.ftn.bsep.pki.session.SessionManager;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/2fa")
public class TwoFactorAuthController {

    @Autowired
    private TwoFactorAuthService twoFAService;

    @Autowired
    private IUserRepository userRepository;
    @Autowired
    private JwtService jwtService;
    @Autowired
    private UserService userService;
    @Autowired
    private SessionManager sessionManager;
    
    private final Logger logger = LoggerFactory.getLogger(TwoFactorAuthController.class);
    
    @PostMapping("/generate")
    public ResponseEntity<ApiResponse> generate2FA(@RequestParam String email) throws Exception {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        String secret = twoFAService.generateSecret();
        user.setSecret2FA(secret);
        user.set2FAEnabled(true);
        userRepository.save(user);
        
        logger.info("Korisnik [{}] je aktivirao dvofaktorsku autentikaciju (2FA).", email);
        
        String qrUrl = twoFAService.generateQRUrl("PKI", email, secret);
        String qrImage = twoFAService.generateQRImage(qrUrl);
        
        logger.info("Generisan QR kod za korisnika [{}]. URL: {}", email, qrUrl);
        
        Map<String, String> data = Map.of("qrImage", "data:image/png;base64," + qrImage);
        return ResponseEntity.ok(ApiResponse.successWithData("2FA aktivirana, skenirajte QR kod", data));
    }

    @PostMapping("/verify")
    public Map<String, Object> verify2FA(@RequestBody Verify2FARequest request, HttpServletRequest req) {
        Long userId = jwtService.parseUserIdFromTempToken(request.getTempToken());
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));
        
        logger.info("Pokušaj verifikacije 2FA koda za korisnika [{}].", user.getEmail());
        
        boolean isValid = twoFAService.verifyCode(user.getSecret2FA(), request.getCode());
        if(isValid) {
            boolean mustChangePassword = userService.mustChangePassword(user);
            String token = jwtService.generateToken(user.getEmail(), user.getRole(), user.getId(), mustChangePassword, true);

            SessionInfo sessionInfo = userService.createSession(jwtService.getTokenClaims(token).getId(), user.getEmail(), req);
            sessionManager.addSession(sessionInfo);
            logger.info("Sesija dodata za korisnika [{}], tokenId=[{}], IP=[{}].",
                    sessionInfo.getEmail(),
                    sessionInfo.getTokenId(),
                    sessionInfo.getIpAddress());
            
            logger.info("2FA verifikacija uspešna za korisnika [{}]. Kreirana nova sesija sa IP {}.",
                    user.getEmail(), sessionInfo.getIpAddress());
            return Map.of("valid", true, "token", token);
        } else {
            logger.warn("Neuspešna 2FA verifikacija za korisnika [{}]. Unet je neispravan kod.", user.getEmail());
            return Map.of("valid", false);
        }
    }
}
