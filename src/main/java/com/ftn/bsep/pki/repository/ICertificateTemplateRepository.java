package com.ftn.bsep.pki.repository;

import com.ftn.bsep.pki.entity.CertificateTemplate;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface ICertificateTemplateRepository extends JpaRepository<CertificateTemplate, Long> {
    List<CertificateTemplate> findByIssuerId(Long issuerId);
}
