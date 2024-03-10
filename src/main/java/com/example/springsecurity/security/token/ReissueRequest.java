package com.example.springsecurity.security.token;

public record ReissueRequest(
        String refreshToken
) {
}
