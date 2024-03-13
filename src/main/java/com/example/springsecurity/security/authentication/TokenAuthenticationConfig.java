package com.example.springsecurity.security.authentication;

import lombok.RequiredArgsConstructor;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;

@RequiredArgsConstructor
public class TokenAuthenticationConfig extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {

    private final TokenAuthenticationService tokenAuthenticationService;

    @Override
    public void configure(HttpSecurity builder) {
        builder.addFilterBefore(
                new TokenAuthenticationFilter(tokenAuthenticationService),
                AuthorizationFilter.class
        );
    }
}
