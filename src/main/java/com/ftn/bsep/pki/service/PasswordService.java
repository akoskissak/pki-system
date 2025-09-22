package com.ftn.bsep.pki.service;

import com.ftn.bsep.pki.entity.Password;
import com.ftn.bsep.pki.entity.PasswordShare;
import com.ftn.bsep.pki.entity.User;
import com.ftn.bsep.pki.repository.IPasswordRepository;
import com.ftn.bsep.pki.repository.IUserRepository;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class PasswordService {
    private final IPasswordRepository passwordRepository;
    private final IUserRepository userRepository;

    public PasswordService(IPasswordRepository passwordRepository, IUserRepository userRepository) {
        this.passwordRepository = passwordRepository;
        this.userRepository = userRepository;
    }

    public Password savePassword(String siteName, String username, String encryptedPassword, User owner) {
        Password password = new Password();
        password.setSiteName(siteName);
        password.setUsername(username);
        password.setOwner(owner);

        // Prva verzija lozinke (za vlasnika)
        PasswordShare ownerShare = new PasswordShare();
        ownerShare.setUserId(owner.getId());
        ownerShare.setEncryptedPassword(encryptedPassword);
        password.getShares().add(ownerShare);

        return passwordRepository.save(password);
    }

    public List<Password> getPasswordsForUser(Long userId) {
        List<Password> ownedPasswords = passwordRepository.findByOwnerId(userId);
        List<Password> sharedPasswords = passwordRepository.findBySharedUserId(userId);
        ownedPasswords.addAll(sharedPasswords);
        return ownedPasswords;
    }
}

