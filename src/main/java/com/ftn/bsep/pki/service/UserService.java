package com.ftn.bsep.pki.service;

import com.ftn.bsep.pki.dto.*;
import com.ftn.bsep.pki.entity.*;
import com.ftn.bsep.pki.repository.ICAUserDetailsRepository;
import com.ftn.bsep.pki.repository.IRoleRepository;
import com.ftn.bsep.pki.repository.IVerificationTokenRepository;
import com.ftn.bsep.pki.repository.IUserRepository;
import com.ftn.bsep.pki.session.SessionInfo;
import jakarta.servlet.http.HttpServletRequest;
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
public class UserService {
  private final IUserRepository userRepository;
  private final IVerificationTokenRepository tokenRepository;
  private final PasswordEncoder passwordEncoder;
  private final EmailService emailService;
  private final IRoleRepository roleRepository;
  private final PasswordStrengthService passwordStrengthService;
  private final Logger logger = LoggerFactory.getLogger(UserService.class);
  private final ICAUserDetailsRepository caUserDetailsRepository;
  private final EncryptionService encryptionService;

  public ApiResponse register(RegisterRequest request) {
    logger.info("Registracija: pokusaj korisnika sa emailom {}", request.getEmail());
    if (userRepository.existsByEmail(request.getEmail())) {
      logger.warn("Registracija neuspesna: email {} vec postoji", request.getEmail());
      return ApiResponse.failure("Email already in use");
    }
    
    if(!isValidEmail(request.getEmail())) {
      logger.warn("Registracija neuspesna: email {} nije validan", request.getEmail());
      return ApiResponse.failure("Email is not valid");
    }

    if (!request.getPassword().equals(request.getConfirmPassword())) {
      logger.warn("Registracija neuspesna: lozinke se ne poklapaju za email {}", request.getEmail());
      return ApiResponse.failure("Passwords do not match");
    }
    Role userRole = roleRepository.findByName(RoleName.END_USER).orElseThrow(() -> {
      logger.error("Registracija neuspesna: Role END_USER nije pronađena");
      return new IllegalStateException("Role END_USER not found");
    });
    
    ApiResponse passwordCheck = passwordStrengthService.validatePassword(request.getPassword());
    if(passwordCheck.getError() != null) {
      logger.warn("Registracija neuspesna: lozinka nije dovoljno jaka za email {}", request.getEmail());
      return passwordCheck;
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
    logger.info("Korisnik {} uspesno kreiran u bazi", request.getEmail());


    String token = UUID.randomUUID().toString();
    VerificationToken verificationToken = new VerificationToken(
      token,
      LocalDateTime.now(),
      LocalDateTime.now().plusHours(24),
      user
    );
    tokenRepository.save(verificationToken);
    logger.info("Verifikacioni token kreiran za korisnika {}", request.getEmail());

    String link = "http://localhost:4200/activate?token=" + token;
    emailService.sendEmail(user.getEmail(), "PKI system account activation", buildEmail(user.getFirstName(), link));
    logger.info("Poslat email za aktivaciju korisniku {}", request.getEmail());

    return ApiResponse.success("Check your mail for activation link");
  }

  public ApiResponse activateAccount(String token) {
    logger.info("Aktivacija naloga: pokusaj sa tokenom {}", token);
    Optional<VerificationToken> optionalToken = tokenRepository.findByToken(token);

    if (optionalToken.isEmpty()) {
      logger.warn("Aktivacija neuspešna: nevažeći token {}", token);
      return ApiResponse.failure("Invalid token");
    }

    VerificationToken verificationToken = optionalToken.get();
    
    if (verificationToken.getExpiresAt().isBefore(LocalDateTime.now())) {
      logger.warn("Aktivacija neuspesna: token {} je istekao", token);
      return ApiResponse.failure("Token is expired");
    }

    User user = verificationToken.getUser();
    user.setEnabled(true);
    userRepository.save(user);
    logger.info("Korisnik {} uspesno aktiviran", user.getEmail());

    tokenRepository.delete(verificationToken);

    return ApiResponse.success("Account activated!");
  }

  private String buildEmail(String name, String link) {
    return "Hello " + name + ",\n\nPlease click the following link to activate your account:\n" + link;
  }
  
  public AuthResult authenticate(String email, String password) {
    logger.info("Korisnik {} je pokusao login", email);
    Optional<User> optionalUser = userRepository.findByEmail(email);
    if (optionalUser.isEmpty()) {
      logger.warn("Login neuspesan: korisnik {} ne postoji", email);
      return new AuthResult(false, "User does not exist");
    }
    
    User user = optionalUser.get();
    
    boolean passwordMatches = passwordEncoder.matches(password, user.getPassword());
    if(!user.isEnabled()) {
      logger.info("Login neuspesan: korisnik {} nije verifikovan", email);
      return new AuthResult(false, "Account is not verified");
    }
    
    if(passwordMatches) {
      logger.info("Korisnik {} se uspesno prijavio", email);
      return new AuthResult(true, "Successful login");
    }
    
    logger.warn("Login neuspesan: pogresan email ili lozinka za korisnika {}", email);
    return new AuthResult(false, "Wrong email or password");
  }
  
  public boolean isValidEmail(String email) {
    if (email == null || email.isEmpty()) return false;
    
    String emailRegex = "^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+$";
    return email.matches(emailRegex);
  }
  
  public SessionInfo createSession(String tokenId, String email, HttpServletRequest request) {
    SessionInfo sessionInfo = new SessionInfo();
    sessionInfo.setTokenId(tokenId);
    sessionInfo.setEmail(email);
    
    String ipAddress = request.getHeader("X-Forwarder-For");
    if(ipAddress != null && !ipAddress.isEmpty()) {
      ipAddress = ipAddress.split(",")[0].trim();
    } else {
      ipAddress = request.getRemoteAddr();
    }
    if("0:0:0:0:0:0:0:1".equals(ipAddress) || "::1".equals(ipAddress)) {
      ipAddress = "127.0.0.1";
    }
    
    sessionInfo.setIpAddress(ipAddress);
    
    sessionInfo.setUserAgent(request.getHeader("User-Agent"));
    sessionInfo.setIssuedAt(LocalDateTime.now());
    sessionInfo.setLastActivity(LocalDateTime.now());
    
    logger.info("Nova sesija kreirana za korisnika {} sa IP {} i User-Agent '{}'",
            email, ipAddress, sessionInfo.getUserAgent());

    return sessionInfo;
  }
  
  public User getByEmail(String email){
    Optional<User> user = userRepository.findByEmail(email);
    if(user.isEmpty()) {
      return null;
    }
    return user.get();
  }
  
  public User createCAUser(CreateCAUserRequest request) {
    if (userRepository.findByEmail(request.getEmail()).isPresent()) {
      logger.warn("Kreiranje CA korisnika neuspesno: korisnik sa email-om {} već postoji", request.getEmail());
      throw new RuntimeException("User with that email already exists");
    }
    String temporaryPassword = UUID.randomUUID().toString().replace("-", "").substring(0, 12);
    
    User user = new User();
    user.setEmail(request.getEmail());
    user.setFirstName(request.getFirstName());
    user.setLastName(request.getLastName());
    
    Role caRole = roleRepository.findByName(RoleName.CA_USER)
            .orElseThrow(() -> new RuntimeException("CA_USER role missing"));
    user.setRole(caRole);
    user.setPassword(passwordEncoder.encode(temporaryPassword));
    user.setEnabled(true);

    // Generisanje i enkripcija simetričnog ključa za CA korisnika
    try {
      String plainUserKey = encryptionService.generateSymmetricKey();
      String encryptedUserKey = encryptionService.encryptUserKey(plainUserKey);
      user.setSymmetricKey(encryptedUserKey);

    } catch (Exception e) {
      logger.error("Greška prilikom generisanja i enkripcije simetričnog ključa za korisnika {}", user.getEmail(), e);
      throw new RuntimeException("Greška prilikom generisanja i enkripcije simetričnog ključa.", e);
    }

    userRepository.save(user);

    CAUserDetails caDetails = new CAUserDetails(user);
    caUserDetailsRepository.save(caDetails);
    
    emailService.sendEmail(request.getEmail(), "PKI system - temporary password for CA_USER", "Hello " + request.getFirstName() + ",\n\nYour temporary password is: " + temporaryPassword);
    logger.info("CA korisnik {} je kreiran sa privremenom lozinkom", user.getEmail());

    return user;
  }
  
  public ApiResponse changePasswordForCAUser(String email, ChangePasswordRequest request) {
    logger.info("CA Korisnik {} je pokusao izmenu privremene lozinke", email);
    Optional<User> optionalUser = userRepository.findByEmail(email);
    if (optionalUser.isEmpty()) {
      logger.warn("Promena lozinke neuspesna: CA korisnik {} ne postoji", email);
      return ApiResponse.failure("User does not exist");
    }

    User user = optionalUser.get();

    if (user.getRole().getName() != RoleName.CA_USER) {
      logger.warn("Promena lozinke neuspesna: korisnik {} nije CA korisnik", email);
      return ApiResponse.failure("User is not a CA user");
    }

    CAUserDetails caUserDetails = caUserDetailsRepository.findByUser(user)
            .orElseThrow(() -> new RuntimeException("CA details not found"));

    if (!caUserDetails.isFirstLogin()) {
      logger.info("Korisnik {} ne mora da menja lozinku", email);
      return ApiResponse.failure("User does not need to change password");
    }
    
    if(!request.getNewPassword().equals(request.getConfirmPassword())) {
      logger.warn("Korisnik {}: nova lozinka i potvrda se ne poklapaju", email);
      return ApiResponse.failure("New password and confirmation do not match");
    }
    
    ApiResponse strengthResponse = passwordStrengthService.validatePassword(request.getNewPassword());
    if(strengthResponse.getError() != null) {
      logger.warn("Korisnik {}: lozinka nije dovoljno jaka", email);
      return strengthResponse;
    }
    
    user.setPassword(passwordEncoder.encode(request.getNewPassword()));
    userRepository.save(user);
    
    caUserDetails.setFirstLogin(false);
    caUserDetailsRepository.save(caUserDetails);

    logger.info("CA korisnik {} je uspesno promenio lozinku", email);
    return ApiResponse.success("Password changed successfully");
  }

  public boolean mustChangePassword(User user) {
    if (user.getRole().getName() == RoleName.CA_USER) {
      CAUserDetails caDetails = caUserDetailsRepository.findByUser(user)
              .orElseThrow(() -> new RuntimeException("CA User details not found for user " + user.getId()));
      return caDetails.isFirstLogin();
    }
    return false;
  }
}
