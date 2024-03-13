package com.example.springsecurity.security.reissue;

import com.example.springsecurity.common.response.Response;
import com.example.springsecurity.security.RefreshToken;
import com.example.springsecurity.security.authentication.TokenAuthenticationService;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.io.IOException;

import static com.example.springsecurity.security.common.SecurityConstants.REDIS_REFRESH_TOKEN_ATTRIBUTE;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@RequiredArgsConstructor
public class TokenReissueSuccessHandler implements AuthenticationSuccessHandler {

    private final ObjectMapper objectMapper;
    private final TokenAuthenticationService tokenAuthenticationService;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException {
        RefreshToken redisRefreshToken = (RefreshToken) request.getAttribute(REDIS_REFRESH_TOKEN_ATTRIBUTE);
        ReissueResponse reissueResponse = tokenAuthenticationService.reissueToken(redisRefreshToken);
        sendSuccessResponse(response, reissueResponse);
    }

    private void sendSuccessResponse(HttpServletResponse response, ReissueResponse reissueResponse)
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
