package com.ftn.bsep.pki.repository;

import com.ftn.bsep.pki.entity.PendingCsrRequest;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface IPendingCsrRepository extends JpaRepository<PendingCsrRequest, Long> {
}
