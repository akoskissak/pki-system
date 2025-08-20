package com.ftn.bsep.pki.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Getter
@Setter
@Table(name = "role")
public class Role {
  @Id
  @Column(name = "id")
  private Long id;

  @Enumerated(EnumType.STRING)
  @Column(unique = true, nullable = false)
  private RoleName name;
}
