package com.ftn.bsep.pki.service;

import com.ftn.bsep.pki.entity.Password;
import com.ftn.bsep.pki.entity.PasswordShare;
import com.ftn.bsep.pki.entity.User;
import com.ftn.bsep.pki.repository.IPasswordRepository;
import com.ftn.bsep.pki.repository.IUserRepository;
import jakarta.transaction.Transactional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

@Service
public class PasswordService {
    private final IPasswordRepository passwordRepository;
    private final IUserRepository userRepository;
    private static final Logger logger = LoggerFactory.getLogger(PasswordService.class);

    public PasswordService(IPasswordRepository passwordRepository, IUserRepository userRepository) {
        this.passwordRepository = passwordRepository;
        this.userRepository = userRepository;
    }

    public Password savePassword(String siteName, String username, String encryptedPassword, User owner) {
        logger.info("Saving new password for site='{}', username='{}', ownerId={} ({})",
                siteName, username, owner.getId(), owner.getEmail());

        Password password = new Password();
        password.setSiteName(siteName);
        password.setUsername(username);
        password.setOwner(owner);

        // Prva verzija lozinke (za vlasnika)
        PasswordShare ownerShare = new PasswordShare();
        ownerShare.setUserId(owner.getId());
        ownerShare.setEncryptedPassword(encryptedPassword);
        ownerShare.setSharedByUserId(owner.getId());
        ownerShare.setSharedAt(Instant.now());
        password.getShares().add(ownerShare);
        
        Password savedPassword = passwordRepository.save(password);
        logger.info("Password id={} successfully saved for ownerId={} ({})",
                savedPassword.getId(), owner.getId(), owner.getEmail());

        return savedPassword;
    }

    @Transactional
    public List<Password> getPasswordsForUser(Long userId) {
        return passwordRepository.findBySharedByUserId(userId);
    }

    @Transactional
    public List<Password> getPasswordsSharedWithUser(Long userId) {
        return passwordRepository.findBySharedUserId(userId);
    }

    public void sharePassword(Long passwordId, Long ownerId, Long targetUserId, String encryptedPasswordForTargetUser) {
        Password password = passwordRepository.findById(passwordId)
                .orElseThrow(() -> {
                    logger.error("Password id={} not found. Share aborted.", passwordId);
                    return new RuntimeException("Password not found");
                });

        // BEZBEDNOSNA PROVERA: Da li je korisnik koji šalje zahtev zaista vlasnik lozinke?
        if (!password.getOwner().getId().equals(ownerId)) {
            logger.warn("User id={} attempted to share password id={} which they do not own", ownerId, passwordId);
            throw new SecurityException("Only the owner can share the password.");
        }

        // Provera da li je lozinka već podeljena sa tim korisnikom
        boolean alreadyShared = password.getShares().stream()
                .anyMatch(share -> share.getUserId().equals(targetUserId));
        if (alreadyShared) {
            logger.warn("Password id={} already shared with userId={}", passwordId, targetUserId);
            throw new RuntimeException("Password already shared with this user.");
        }

        // Pronalazimo korisnika sa kim se deli, da bismo bili sigurni da postoji
        User targetUser = userRepository.findById(targetUserId)
                .orElseThrow(() -> {
                    logger.error("Target user id={} not found. Cannot share password id={}", targetUserId, passwordId);
                    return new RuntimeException("Target user not found.");
                });

        PasswordShare newShare = new PasswordShare();
        newShare.setUserId(targetUserId);
        newShare.setEncryptedPassword(encryptedPasswordForTargetUser);
        newShare.setSharedByUserId(ownerId);
        newShare.setSharedAt(Instant.now());
        password.getShares().add(newShare);
        passwordRepository.save(password);

        logger.info("Password id={} successfully shared by ownerId={} with targetUserId={} ({})",
                passwordId, ownerId, targetUserId, targetUser.getEmail());

    }

    public void deletePassword(Long passwordId) {
        passwordRepository.deleteById(passwordId);
    }

    public Optional<Password> getPasswordById(Long passwordId) {
        return passwordRepository.findById(passwordId);
    }
}

