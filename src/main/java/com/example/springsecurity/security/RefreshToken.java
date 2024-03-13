package com.example.springsecurity.security;

import lombok.Builder;

@Builder
public record RefreshToken(
        String uuid,
        String email,
        String authorities,
        String refreshToken
) {
    public static RefreshToken from(String uuid, String email, String authorities, String refreshToken) {
        return RefreshToken.builder()
                .uuid(uuid)
                .email(email)
                .authorities(authorities)
                .refreshToken(refreshToken)
                .build();
    }
}
