package com.example.springsecurity.security.reissue;

import com.example.springsecurity.common.exception.CustomException;
import com.example.springsecurity.common.exception.ErrorCode;
import com.example.springsecurity.security.authentication.TokenAuthenticationService;
import com.example.springsecurity.security.RefreshToken;
import com.example.springsecurity.common.exception.CustomAuthenticationException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

import static com.example.springsecurity.common.exception.ErrorCode.*;
import static com.example.springsecurity.security.common.SecurityConstants.REDIS_REFRESH_TOKEN_ATTRIBUTE;

@RequiredArgsConstructor
public class TokenReissueFilter extends OncePerRequestFilter {

    private final RequestMatcher reissueRequestMatcher;
    private final ObjectMapper objectMapper;
    private final TokenAuthenticationService tokenAuthenticationService;
    private final TokenReissueSuccessHandler successHandler;
    private final TokenReissueFailureHandler failureHandler;

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain) throws ServletException, IOException {
        if (!isReissueRequest(request)) {
            filterChain.doFilter(request, response);
            return;
        }

        String refreshToken = getRefreshToken(request);
        if (refreshToken == null) {
            unsuccessfulAuthentication(request, response, NOT_TOKEN);
        }

        try {
            RefreshToken redisRefreshToken = tokenAuthenticationService.validateRefreshToken(refreshToken);
            request.setAttribute(REDIS_REFRESH_TOKEN_ATTRIBUTE, redisRefreshToken);
            successfulAuthentication(request, response);
        } catch (ExpiredJwtException e) {
            unsuccessfulAuthentication(request, response, EXPIRED_TOKEN);
        } catch (SignatureException | MalformedJwtException | UnsupportedJwtException | IllegalArgumentException e) {
            unsuccessfulAuthentication(request, response, INVALID_TOKEN);
        }
    }

    private boolean isReissueRequest(HttpServletRequest request) {
        return reissueRequestMatcher.matches(request);
    }

    public String getRefreshToken(HttpServletRequest request) {
        try {
            ReissueRequest reissueRequest = objectMapper.readValue(request.getReader(), ReissueRequest.class);
            return reissueRequest.refreshToken();
        } catch (IOException e) {
            throw new CustomException(INVALID_REQUEST);
        }
    }

    private void successfulAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        successHandler.onAuthenticationSuccess(request, response, null);
    }

    private void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                            ErrorCode errorCode) throws IOException {
        String errorMessage = errorCode.getMessage();
        AuthenticationException exception = new CustomAuthenticationException(errorMessage);
        failureHandler.onAuthenticationFailure(request, response, exception);
    }
}
