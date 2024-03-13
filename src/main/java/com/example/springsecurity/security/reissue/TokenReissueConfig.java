package com.example.springsecurity.security.reissue;

import com.example.springsecurity.security.authentication.TokenAuthenticationService;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import static com.example.springsecurity.security.common.SecurityConstants.DEFAULT_HTTP_METHOD;
import static com.example.springsecurity.security.common.SecurityConstants.REISSUE_URL_PATTERN;

@RequiredArgsConstructor
public class TokenReissueConfig extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {

    private final ObjectMapper objectMapper;
    private final TokenAuthenticationService tokenAuthenticationService;

    @Override
    public void configure(HttpSecurity builder) {
        TokenReissueFilter tokenReissueFilter = new TokenReissueFilter(
                reissueRequestMatcher(),
                objectMapper,
                tokenAuthenticationService,
                tokenReissueSuccessHandler(),
                tokenReissueFailureHandler()
        );
        builder.addFilterBefore(
                tokenReissueFilter,
                UsernamePasswordAuthenticationFilter.class
        );
    }

    private AntPathRequestMatcher reissueRequestMatcher() {
        return new AntPathRequestMatcher(REISSUE_URL_PATTERN, DEFAULT_HTTP_METHOD);
    }

    public TokenReissueSuccessHandler tokenReissueSuccessHandler() {
        return new TokenReissueSuccessHandler(objectMapper, tokenAuthenticationService);
    }

    public TokenReissueFailureHandler tokenReissueFailureHandler() {
        return new TokenReissueFailureHandler(objectMapper);
    }
}
