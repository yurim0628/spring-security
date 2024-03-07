package com.example.springsecurity.security.login;

public record LoginRequest(
        String email,
        String password
) {
}
