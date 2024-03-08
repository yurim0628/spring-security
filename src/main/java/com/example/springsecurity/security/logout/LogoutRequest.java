package com.example.springsecurity.security.logout;

public record LogoutRequest(
        String accessToken,
        String refreshToken
) {
}
