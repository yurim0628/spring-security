package com.example.springsecurity.security.token;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import static com.example.springsecurity.security.common.SecurityConstants.DEFAULT_HTTP_METHOD;
import static com.example.springsecurity.security.common.SecurityConstants.REISSUE_URL_PATTERN;

@RequiredArgsConstructor
public class TokenAuthenticationConfig extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {

    private static final AntPathRequestMatcher DEFAULT_ANT_REISSUE_REQUEST_MATCHER
            = new AntPathRequestMatcher(REISSUE_URL_PATTERN, DEFAULT_HTTP_METHOD);
    private final ObjectMapper objectMapper;
    private final TokenAuthenticationService tokenAuthenticationService;

    @Override
    public void configure(HttpSecurity builder) {
        builder.addFilterBefore(
                new TokenAuthenticationFilter(DEFAULT_ANT_REISSUE_REQUEST_MATCHER, objectMapper, tokenAuthenticationService),
                AuthorizationFilter.class
        );
    }
}
