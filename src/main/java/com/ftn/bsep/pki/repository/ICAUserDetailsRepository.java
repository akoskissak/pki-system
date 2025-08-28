package com.ftn.bsep.pki.repository;

import com.ftn.bsep.pki.entity.CAUserDetails;
import com.ftn.bsep.pki.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface ICAUserDetailsRepository extends JpaRepository<CAUserDetails, Long> {
    Optional<CAUserDetails> findByUser(User user);
}
