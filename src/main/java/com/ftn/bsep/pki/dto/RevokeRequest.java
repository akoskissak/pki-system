package com.ftn.bsep.pki.dto;

// RevokeDto.java
public class RevokeRequest {
    private int reason;

    // Jackson može da koristi ovaj prazan konstruktor
    public RevokeRequest() {}

    // Jackson koristi ovaj setter da postavi vrednost iz JSON-a
    public void setReason(int reason) {
        this.reason = reason;
    }

    public int getReason() {
        return reason;
    }
}
