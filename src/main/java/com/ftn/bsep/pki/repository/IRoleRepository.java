package com.ftn.bsep.pki.repository;

import com.ftn.bsep.pki.entity.Role;
import com.ftn.bsep.pki.entity.RoleName;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface IRoleRepository extends JpaRepository<Role, Long> {
  Optional<Role> findByName(RoleName name);
}
