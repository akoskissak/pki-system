package com.ftn.bsep.pki.repository;

import com.ftn.bsep.pki.entity.Password;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;

public interface IPasswordRepository extends JpaRepository<Password, Long> {

    List<Password> findByOwnerId(Long ownerId);

    @Query("SELECT p FROM Password p JOIN p.shares s WHERE s.userId = ?1")
    List<Password> findBySharedUserId(Long userId);
}
