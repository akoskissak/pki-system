package com.ftn.bsep.pki.repository;

import com.ftn.bsep.pki.entity.Certificate;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface ICertificateRepository extends JpaRepository<Certificate, Long> {
}
