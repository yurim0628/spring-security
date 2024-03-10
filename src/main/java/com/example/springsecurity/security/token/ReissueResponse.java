package com.example.springsecurity.security.token;

import com.example.springsecurity.security.token.common.Token;
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
