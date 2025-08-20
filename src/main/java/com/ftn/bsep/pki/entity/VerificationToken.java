package com.ftn.bsep.pki.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;

@Entity
@Getter
@Setter
@NoArgsConstructor
@Table(name = "verification_token")
public class VerificationToken {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(unique = true)
  private String token;

  private LocalDateTime createdAt;
  private LocalDateTime expiresAt;

  @OneToOne
  @JoinColumn(name = "user_id")
  private User user;

  public VerificationToken(String token, LocalDateTime createdAt, LocalDateTime expiresAt, User user) {
    this.token = token;
    this.createdAt = createdAt;
    this.expiresAt = expiresAt;
    this.user = user;
  }
}
