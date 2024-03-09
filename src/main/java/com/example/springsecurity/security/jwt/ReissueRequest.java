package com.example.springsecurity.security.jwt;

public record ReissueRequest(
        String refreshToken
) {
}
