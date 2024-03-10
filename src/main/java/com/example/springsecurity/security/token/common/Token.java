package com.example.springsecurity.security.token.common;

import lombok.Builder;

@Builder
public record Token(
        String grantType,
        String accessToken,
        String refreshToken
) {
}
