package com.ftn.bsep.pki.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.util.HashSet;
import java.util.Set;

@Entity
@Getter
@Setter
@Table(name = "users")
public class User {
  @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(unique = true, nullable = false)
  private String email;

  @Column(nullable = false)
  private String password;

  private String firstName;
  private String lastName;
  private String organization;

  private boolean enabled = false;

  @ManyToOne(fetch = FetchType.EAGER)
  @JoinColumn(name = "role_id", referencedColumnName = "id")
  private Role role;

  @Column(name = "symmetric_key", columnDefinition = "TEXT")
  private String symmetricKey;
  
}
