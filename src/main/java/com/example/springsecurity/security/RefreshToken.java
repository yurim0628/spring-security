package com.example.springsecurity.security;

import lombok.Builder;

@Builder
public record RefreshToken(
        String email,
        String authorities,
        String refreshToken
) {
    public static RefreshToken from(String email, String authorities, String refreshToken) {
        return RefreshToken.builder()
                .email(email)
                .authorities(authorities)
                .refreshToken(refreshToken)
                .build();
    }
}
