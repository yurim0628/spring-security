package com.example.springsecurity.security.jwt;

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
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

import static com.example.springsecurity.common.exception.ErrorCode.*;
import static com.example.springsecurity.security.common.SecurityConstants.*;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final AntPathRequestMatcher reissueRequestMatcher
            = new AntPathRequestMatcher("/reissue", "POST");

    private final ObjectMapper objectMapper;
    private final JwtService jwtService;

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain) throws ServletException, IOException {
        String accessToken = getAccessToken(request);

        if (accessToken == null) {
            boolean isReissueRequest = isReissueRequest(request);

            if (isReissueRequest) {
                String refreshToken = getRefreshToken(request);
                ReissueResponse reissueResponse = jwtService.reissueToken(refreshToken);
                sendResponse(response, reissueResponse);
                return;
            }

            filterChain.doFilter(request, response);
            return;
        }

        try {
            Authentication authentication = jwtService.getAuthentication(accessToken);
            boolean isBlackListToken = jwtService.isBlackListToken(accessToken);

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
