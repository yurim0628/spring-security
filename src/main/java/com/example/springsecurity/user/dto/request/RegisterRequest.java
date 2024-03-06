package com.example.springsecurity.user.dto.request;

import com.example.springsecurity.user.model.User;

public record RegisterRequest(
        String email,
        String password
) {
    public User of(String encodedPassword) {
        return User.builder()
                .email(email)
                .password(encodedPassword)
                .build();
    }
}
