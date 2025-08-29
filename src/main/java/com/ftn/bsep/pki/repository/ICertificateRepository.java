package com.ftn.bsep.pki.repository;

import com.ftn.bsep.pki.entity.Certificate;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface ICertificateRepository extends JpaRepository<Certificate, Long> {

    List<Certificate> findAllByOwnerId(Long ownerId);

    @Query("SELECT c FROM Certificate c " +
            "WHERE c.subjectOrganization = :orgName")
    List<Certificate> findAllByOrganization(@Param("orgName") String orgName);
}
