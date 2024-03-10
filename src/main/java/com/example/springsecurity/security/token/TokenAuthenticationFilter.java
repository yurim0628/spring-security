package com.example.springsecurity.security.token;

import com.example.springsecurity.common.exception.CustomException;
import com.example.springsecurity.common.response.Response;
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
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

import static com.example.springsecurity.common.exception.ErrorCode.*;
import static com.example.springsecurity.security.common.SecurityConstants.*;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@RequiredArgsConstructor
public class TokenAuthenticationFilter extends OncePerRequestFilter {

    private final RequestMatcher reissueRequestMatcher;
    private final ObjectMapper objectMapper;
    private final TokenAuthenticationService tokenAuthenticationService;

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain) throws ServletException, IOException {
        String accessToken = getAccessToken(request);

        if (accessToken == null) {
            boolean isReissueRequest = isReissueRequest(request);

            if (isReissueRequest) {
                String refreshToken = getRefreshToken(request);
                ReissueResponse reissueResponse = tokenAuthenticationService.reissueToken(refreshToken);
                sendResponse(response, reissueResponse);
                return;
            }

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

    private void sendResponse(HttpServletResponse response, ReissueResponse reissueResponse)
            throws IOException {
        response.setContentType(APPLICATION_JSON_VALUE);
        response.setCharacterEncoding(UTF_8.name());
        response.setStatus(HttpStatus.OK.value());
        objectMapper.writeValue(
                response.getWriter(),
                Response.success(reissueResponse)
        );
    }
}
