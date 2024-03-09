package com.example.springsecurity.security.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;

@RequiredArgsConstructor
public class JwtAuthenticationConfig extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {

    private final ObjectMapper objectMapper;
    private final JwtService jwtService;

    @Override
    public void configure(HttpSecurity builder) {
        builder.addFilterBefore(
                new JwtAuthenticationFilter(objectMapper, jwtService),
                AuthorizationFilter.class
        );
    }
}
