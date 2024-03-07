package com.example.springsecurity.security.jwt;

import lombok.Builder;

@Builder
public record RefreshToken(
        String email,
        String refreshToken
) {
    public static RefreshToken from(String email, String refreshToken) {
        return RefreshToken.builder()
                .email(email)
                .refreshToken(refreshToken)
                .build();
    }
}
