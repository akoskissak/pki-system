package com.ftn.bsep.pki.repository;

import com.ftn.bsep.pki.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface IUserRepository extends JpaRepository<User, Long> {
  Boolean existsByEmail(String email);
}
