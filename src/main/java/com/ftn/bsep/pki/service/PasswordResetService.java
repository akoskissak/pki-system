package com.ftn.bsep.pki.service;

import com.ftn.bsep.pki.dto.ApiResponse;
import com.ftn.bsep.pki.dto.AuthResult;
import com.ftn.bsep.pki.dto.ResetPasswordRequest;
import com.ftn.bsep.pki.entity.PasswordResetToken;
import com.ftn.bsep.pki.entity.User;
import com.ftn.bsep.pki.repository.IPasswordResetTokenRepository;
import com.ftn.bsep.pki.repository.IUserRepository;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class PasswordResetService {
    private final IUserRepository userRepository;
    private final IPasswordResetTokenRepository passwordResetTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;
    private final PasswordStrengthService passwordStrengthService;
    private static final Logger logger = LoggerFactory.getLogger(PasswordResetService.class);

    public AuthResult createPasswordResetToken(String email) {
        Optional<User> optionalUser = userRepository.findByEmail(email);
        if(optionalUser.isEmpty()) {
            logger.warn("Pokusaj resetovanja lozinke za nepostojeceg korisnika: {}", email);
            return new AuthResult(false, "User does not exist");
        }
        
        User user = optionalUser.get();
        
        Optional<PasswordResetToken> existingTokenOptional = passwordResetTokenRepository.findByUser(user)
                .filter(t -> t.getExpiresAt().isAfter(LocalDateTime.now()));
        
        PasswordResetToken resetToken;
        if(existingTokenOptional.isPresent()) {
            logger.info("Postoji vazeci token za reset lozinke korisnika {}", email);
            resetToken = existingTokenOptional.get();
        } else {
            String token = UUID.randomUUID().toString();
            LocalDateTime expiresAt = LocalDateTime.now().plusMinutes(15);

            resetToken = new PasswordResetToken();
            resetToken.setToken(token);
            resetToken.setUser(user);
            resetToken.setExpiresAt(expiresAt);
            resetToken.setCreatedAt(LocalDateTime.now());
            passwordResetTokenRepository.save(resetToken);

            logger.info("Kreiran novi token za reset lozinke za korisnika {}", email);
        }

        String resetUrl = "https://localhost:4200/reset-password?token=" + resetToken.getToken();

        emailService.sendEmail(user.getEmail(), "PKI system account password reset", buildEmail(user.getFirstName(), resetUrl));
        logger.info("Poslat email za reset lozinke korisniku {}", email);

        return new AuthResult(true, "Successfully sent password reset email");
    }
    
    
    private String buildEmail(String name, String link) {
        return "Hello " + name + ",\n\nYou have 15 minutes to click the following link to reset your password:\n" + link; 
    }
    
    public ApiResponse resetPassword(ResetPasswordRequest request) {
        Optional<PasswordResetToken> optionalResetToken = passwordResetTokenRepository.findByToken(request.getToken());
        if(optionalResetToken.isEmpty()) {
            logger.warn("Pokusaj resetovanja lozinke neuspesan – nevalidan token: {}", request.getToken());
            return ApiResponse.failure("Invalid token");
        }
        
        if (!request.getNewPassword().equals(request.getConfirmPassword())) {
            logger.warn("Pokusaj resetovanja lozinke neuspesan – lozinke se ne poklapaju (userId={})", optionalResetToken.get().getUser().getId());
            return ApiResponse.failure("Passwords do not match");
        }

        ApiResponse response = passwordStrengthService.validatePassword(request.getNewPassword());
        if(response.getError() != null) {
            logger.warn("Pokusaj resetovanja lozinke neuspesan – lozinka nije dovoljno jaka (userId={})", optionalResetToken.get().getUser().getId());

            return response;
        }
        
        PasswordResetToken resetToken = optionalResetToken.get();
        
        if(resetToken.getExpiresAt().isBefore(LocalDateTime.now())) {
            logger.warn("Pokusaj resetovanja lozinke neuspesan – token istekao (userId={})", resetToken.getUser().getId());
            return ApiResponse.failure("Token is expired");
        }
        
        User user = resetToken.getUser();
        if(passwordEncoder.matches(request.getNewPassword(), user.getPassword())) {
            logger.warn("Pokusaj resetovanja lozinke neuspesan – nova lozinka ista kao stara (userId={})", user.getId());
            return ApiResponse.failure("Cannot change password on the same password");
        }
        
        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        userRepository.save(user);
        
        passwordResetTokenRepository.delete(resetToken);
        
        logger.info("Lozinka uspesno resetovana za korisnika: {}", user.getEmail());
        return ApiResponse.success("Successfully reset password");
    }
}
