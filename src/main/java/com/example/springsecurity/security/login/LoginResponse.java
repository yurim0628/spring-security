package com.example.springsecurity.security.login;

import com.example.springsecurity.security.Token;
import lombok.Builder;

@Builder
public record LoginResponse(
        Token token
) {
    public static LoginResponse from(Token token) {
        return LoginResponse.builder()
                .token(token)
                .build();
    }
}
