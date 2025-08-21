package com.ftn.bsep.pki.repository;

import com.ftn.bsep.pki.entity.PasswordResetToken;
import com.ftn.bsep.pki.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface IPasswordResetTokenRepository extends JpaRepository<PasswordResetToken, Long> {
    Optional<PasswordResetToken> findByToken(String token);
    Optional<PasswordResetToken> findByUser(User user);
}
