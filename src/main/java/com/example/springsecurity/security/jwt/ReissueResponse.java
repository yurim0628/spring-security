package com.example.springsecurity.security.jwt;

import com.example.springsecurity.security.Token;
import lombok.Builder;

@Builder
public record ReissueResponse(
        Token token
) {
    public static ReissueResponse from(Token token) {
        return ReissueResponse.builder()
                .token(token)
                .build();
    }
}
