package com.example.springsecurity.security.authentication;

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
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

import static com.example.springsecurity.common.exception.ErrorCode.*;
import static com.example.springsecurity.security.common.SecurityConstants.*;

@RequiredArgsConstructor
public class TokenAuthenticationFilter extends OncePerRequestFilter {

    private final TokenAuthenticationService tokenAuthenticationService;

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain) throws ServletException, IOException {
        String accessToken = getAccessToken(request);

        if (accessToken == null) {
            request.setAttribute(EXCEPTION_ATTRIBUTE, NOT_TOKEN);
            filterChain.doFilter(request, response);
            return;
        }

        try {
            Authentication authentication = tokenAuthenticationService.getAuthentication(accessToken);
            boolean isBlackListToken = tokenAuthenticationService.isBlackListToken(accessToken);

            if (isBlackListToken) {
                request.setAttribute(EXCEPTION_ATTRIBUTE, BLACKLIST_TOKEN);
                filterChain.doFilter(request, response);
                return;
            }

            setAuthentication(authentication);
        } catch (ExpiredJwtException e) {
            request.setAttribute(EXCEPTION_ATTRIBUTE, EXPIRED_TOKEN);
        } catch (SignatureException | MalformedJwtException | UnsupportedJwtException | IllegalArgumentException e) {
            request.setAttribute(EXCEPTION_ATTRIBUTE, INVALID_TOKEN);
        }

        filterChain.doFilter(request, response);
    }

    private String getAccessToken(HttpServletRequest request) {
        String accessTokenHeader = request.getHeader(ACCESS_TOKEN_HEADER);
        if (accessTokenHeader != null && accessTokenHeader.startsWith(BEARER_PREFIX)) {
            return accessTokenHeader.substring(BEARER_PREFIX_LENGTH);
        }
        return null;
    }

    private void setAuthentication(Authentication authentication) {
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }
}
