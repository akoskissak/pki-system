package com.ftn.bsep.pki.entity;

import lombok.Getter;
import lombok.Setter;
import org.bouncycastle.asn1.x500.X500Name;

import java.math.BigInteger;
import java.security.PrivateKey;

@Getter
@Setter
public class Issuer {
    private X500Name x500Name;
    private PrivateKey privateKey;
    private BigInteger serialNumber;
}
