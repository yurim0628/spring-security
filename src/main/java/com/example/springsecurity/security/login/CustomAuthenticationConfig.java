package com.example.springsecurity.security.login;

import com.example.springsecurity.security.jwt.JwtService;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@RequiredArgsConstructor
public class CustomAuthenticationConfig extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {

    private final ObjectMapper objectMapper;
    private final JwtService jwtService;

    @Override
    public void configure(HttpSecurity http) {
        AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);
        http.addFilterBefore(
                customAuthenticationFilter(authenticationManager),
                UsernamePasswordAuthenticationFilter.class
        );
    }

    public CustomAuthenticationFilter customAuthenticationFilter(AuthenticationManager authenticationManager) {
        CustomAuthenticationFilter customAuthenticationFilter = new CustomAuthenticationFilter(objectMapper);

        customAuthenticationFilter.setAuthenticationManager(authenticationManager);
        customAuthenticationFilter.setAuthenticationSuccessHandler(customAuthenticationSuccessHandler());
        customAuthenticationFilter.setAuthenticationFailureHandler(customAuthenticationFailureHandler());

        return customAuthenticationFilter;
    }

    public CustomAuthenticationSuccessHandler customAuthenticationSuccessHandler() {
        return new CustomAuthenticationSuccessHandler(objectMapper, jwtService);
    }

    public CustomAuthenticationFailureHandler customAuthenticationFailureHandler() {
        return new CustomAuthenticationFailureHandler(objectMapper);
    }
}

