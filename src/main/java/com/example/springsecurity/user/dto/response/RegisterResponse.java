package com.example.springsecurity.user.dto.response;

import com.example.springsecurity.user.model.User;
import lombok.Builder;

@Builder
public record RegisterResponse (
        Long id,
        String email
){
    public static RegisterResponse from(User user) {
        return RegisterResponse.builder()
                .id(user.getId())
                .email(user.getEmail())
                .build();
    }
}
