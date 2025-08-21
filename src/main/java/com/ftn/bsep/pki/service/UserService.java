package com.ftn.bsep.pki.service;

import com.ftn.bsep.pki.dto.ApiResponse;
import com.ftn.bsep.pki.dto.AuthResult;
import com.ftn.bsep.pki.dto.RegisterRequest;
import com.ftn.bsep.pki.entity.Role;
import com.ftn.bsep.pki.entity.RoleName;
import com.ftn.bsep.pki.entity.User;
import com.ftn.bsep.pki.entity.VerificationToken;
import com.ftn.bsep.pki.repository.IRoleRepository;
import com.ftn.bsep.pki.repository.IVerificationTokenRepository;
import com.ftn.bsep.pki.repository.IUserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class UserService {
  private final IUserRepository userRepository;
  private final IVerificationTokenRepository tokenRepository;
  private final PasswordEncoder passwordEncoder;
  private final EmailService emailService;
  private final IRoleRepository roleRepository;
  private final PasswordStrengthService passwordStrengthService;

  public ApiResponse register(RegisterRequest request) {
    if (userRepository.existsByEmail(request.getEmail())) {
      return ApiResponse.failure("Email already in use");
    }
    
    if(!isValidEmail(request.getEmail())) {
      return ApiResponse.failure("Email is not valid");
    }

    if (!request.getPassword().equals(request.getConfirmPassword())) {
      return ApiResponse.failure("Passwords do not match");
    }
    Role userRole = roleRepository.findByName(RoleName.END_USER).orElseThrow(() -> new IllegalStateException("Role END_USER not found"));
    
    ApiResponse response = passwordStrengthService.validatePassword(request.getPassword());
    if(response.getError() != null) {
      return response;
    }
    
    User user = new User();
    user.setEmail(request.getEmail());
    user.setPassword(passwordEncoder.encode(request.getPassword()));
    user.setFirstName(request.getFirstName());
    user.setLastName(request.getLastName());
    user.setOrganization(request.getOrganization());
    user.setEnabled(false);
    user.setRole(userRole);

    userRepository.save(user);

    String token = UUID.randomUUID().toString();
    VerificationToken verificationToken = new VerificationToken(
      token,
      LocalDateTime.now(),
      LocalDateTime.now().plusHours(24),
      user
    );
    tokenRepository.save(verificationToken);

    String link = "http://localhost:4200/activate?token=" + token;
    emailService.sendEmail(user.getEmail(), "PKI system account activation", buildEmail(user.getFirstName(), link));
    
    return ApiResponse.success("Check your mail for activation link");
  }

  public ApiResponse activateAccount(String token) {
    Optional<VerificationToken> optionalToken = tokenRepository.findByToken(token);

    if (optionalToken.isEmpty()) {
      return ApiResponse.failure("Invalid token");
    }

    VerificationToken verificationToken = optionalToken.get();
    
    if (verificationToken.getExpiresAt().isBefore(LocalDateTime.now())) {
      return ApiResponse.failure("Token is expired");
    }

    User user = verificationToken.getUser();
    user.setEnabled(true);
    userRepository.save(user);

    tokenRepository.delete(verificationToken);
    return ApiResponse.success("Account activated!");
  }

  private String buildEmail(String name, String link) {
    return "Hello " + name + ",\n\nPlease click the following link to activate your account:\n" + link;
  }
  
  public AuthResult authenticate(String email, String password) {
    Optional<User> optionalUser = userRepository.findByEmail(email);
    if (optionalUser.isEmpty()) {
      return new AuthResult(false, "User does not exist");
    }
    
    User user = optionalUser.get();
    
    boolean passwordMatches = passwordEncoder.matches(password, user.getPassword());
    if(!user.isEnabled())
      return new AuthResult(false, "Account is not verified");
    
    if(passwordMatches)
      return new AuthResult(true, "Successful login");
    
    return new AuthResult(false, "Wrong email or password");
  }
  
  public boolean isValidEmail(String email) {
    if (email == null || email.isEmpty()) return false;
    
    String emailRegex = "^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+$";
    return email.matches(emailRegex);
  }
}
