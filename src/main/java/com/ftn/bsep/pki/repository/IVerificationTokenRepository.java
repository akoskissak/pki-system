package com.ftn.bsep.pki.repository;

import com.ftn.bsep.pki.entity.VerificationToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface IVerificationTokenRepository extends JpaRepository<VerificationToken, Long> {
  Optional<VerificationToken> findByToken(String token);
}
