package com.ftn.bsep.pki.entity;

import lombok.Getter;
import lombok.Setter;
import org.bouncycastle.asn1.x500.X500Name;
import java.security.PublicKey;
import java.math.BigInteger;
import java.util.Date;

@Getter
@Setter
public class Subject {
    private PublicKey publicKey;
    private X500Name x500Name;
    private BigInteger serialNumber;
    private Date startDate;
    private Date endDate;
    
}
