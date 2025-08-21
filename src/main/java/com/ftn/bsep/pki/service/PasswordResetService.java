package com.ftn.bsep.pki.service;

import com.ftn.bsep.pki.dto.ApiResponse;
import com.ftn.bsep.pki.dto.AuthResult;
import com.ftn.bsep.pki.dto.ResetPasswordRequest;
import com.ftn.bsep.pki.entity.PasswordResetToken;
import com.ftn.bsep.pki.entity.User;
import com.ftn.bsep.pki.repository.IPasswordResetTokenRepository;
import com.ftn.bsep.pki.repository.IUserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
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
    private final JavaMailSender mailSender;
    private final EmailService emailService;
    private final PasswordStrengthService passwordStrengthService;

    public AuthResult createPasswordResetToken(String email) {
        Optional<User> optionalUser = userRepository.findByEmail(email);
        if(optionalUser.isEmpty()) {
            return new AuthResult(false, "User does not exist");
        }
        
        User user = optionalUser.get();
        
        Optional<PasswordResetToken> existingTokenOptional = passwordResetTokenRepository.findByUser(user)
                .filter(t -> t.getExpiresAt().isAfter(LocalDateTime.now()));
        
        PasswordResetToken resetToken;
        if(existingTokenOptional.isPresent()) {
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
        }

        String resetUrl = "http://localhost:4200/reset-password?token=" + resetToken.getToken();

        emailService.sendEmail(user.getEmail(), "PKI system account password reset", buildEmail(user.getFirstName(), resetUrl));
        return new AuthResult(true, "Successfully sent password reset email");
    }
    
    
    private String buildEmail(String name, String link) {
        return "Hello " + name + ",\n\nYou have 15 minutes to click the following link to reset your password:\n" + link; 
    }
    
    public ApiResponse resetPassword(ResetPasswordRequest request) {
        Optional<PasswordResetToken> optionalResetToken = passwordResetTokenRepository.findByToken(request.getToken());
        if(optionalResetToken.isEmpty()) {
            return ApiResponse.failure("Invalid token");
        }
        
        if (!request.getNewPassword().equals(request.getConfirmPassword())) {
            return ApiResponse.failure("Passwords do not match");
        }

        ApiResponse response = passwordStrengthService.validatePassword(request.getNewPassword());
        if(response.getError() != null) {
            return response;
        }
        
        PasswordResetToken resetToken = optionalResetToken.get();
        
        if(resetToken.getExpiresAt().isBefore(LocalDateTime.now())) {
            return ApiResponse.failure("Token is expired");
        }
        
        User user = resetToken.getUser();
        if(passwordEncoder.matches(request.getNewPassword(), user.getPassword())) {
            return ApiResponse.failure("Cannot change password on the same password");
        }
        
        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        userRepository.save(user);
        
        passwordResetTokenRepository.delete(resetToken);
        return ApiResponse.success("Successfully reset password");
    }
}
