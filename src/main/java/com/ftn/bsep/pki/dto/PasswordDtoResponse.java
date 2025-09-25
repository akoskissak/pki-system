package com.ftn.bsep.pki.dto;

import java.time.Instant;
import java.util.List;

public class PasswordDtoResponse {
    private Long id;
    private String siteName;
    private String username;
    private Long ownerId;
    private Instant createdAt;
    private List<SharedPasswordDtoResponse> shares;

    public PasswordDtoResponse(Long id, String siteName, String username, Long ownerId, Instant createdAt) {
        this.id = id;
        this.siteName = siteName;
        this.username = username;
        this.ownerId = ownerId;
    }

    public PasswordDtoResponse() {}

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getSiteName() {
        return siteName;
    }

    public void setSiteName(String siteName) {
        this.siteName = siteName;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public Long getOwnerId() {
        return ownerId;
    }

    public void setOwnerId(Long ownerId) {
        this.ownerId = ownerId;
    }

    public List<SharedPasswordDtoResponse> getShares() {
        return shares;
    }

    public void setShares(List<SharedPasswordDtoResponse> shares) {
        this.shares = shares;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }
}
