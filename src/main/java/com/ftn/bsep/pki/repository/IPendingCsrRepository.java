package com.ftn.bsep.pki.repository;

import com.ftn.bsep.pki.entity.PendingCsrRequest;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface IPendingCsrRepository extends JpaRepository<PendingCsrRequest, Long> {
    List<PendingCsrRequest> findByIssuerId(String issuerId);
    List<PendingCsrRequest> findByIssuerIdIn(List<String> issuerIds);
}
