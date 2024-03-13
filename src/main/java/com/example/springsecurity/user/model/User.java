package com.example.springsecurity.user.model;

import jakarta.persistence.*;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

import static com.example.springsecurity.user.model.Authority.ROLE_USER;
import static jakarta.persistence.GenerationType.IDENTITY;
import static lombok.AccessLevel.PROTECTED;

@Getter
@NoArgsConstructor(access = PROTECTED)
@Entity
@Table(name = "users")
public class User {

    @Id
    @GeneratedValue(strategy = IDENTITY)
    private Long id;

    private String email;
    private String password;

    @Enumerated(EnumType.STRING)
    private Authority authority;

    private int failedLoginAttempts;
    private LocalDateTime lockExpiration;

    @Builder
    private User(
            String email,
            String password
    ) {
        this.email = email;
        this.password = password;
        this.authority = ROLE_USER;
    }

    public void setFailedLoginAttempts(int failedLoginAttempts) {
        this.failedLoginAttempts = failedLoginAttempts;
    }

    public void setLockExpiration(LocalDateTime lockExpiration) {
        this.lockExpiration = lockExpiration;
    }
}
