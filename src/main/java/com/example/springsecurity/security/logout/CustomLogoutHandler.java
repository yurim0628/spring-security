package com.example.springsecurity.security.logout;

import com.example.springsecurity.common.exception.CustomException;
import com.example.springsecurity.security.authentication.TokenAuthenticationService;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;

import java.io.IOException;

import static com.example.springsecurity.common.exception.ErrorCode.INVALID_REQUEST;

@RequiredArgsConstructor
public class CustomLogoutHandler implements LogoutHandler {

    private final ObjectMapper objectMapper;
    private final TokenAuthenticationService tokenAuthenticationService;

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        try {
            LogoutRequest logoutRequest = objectMapper.readValue(request.getReader(), LogoutRequest.class);

            String refreshToken = logoutRequest.refreshToken();
            tokenAuthenticationService.removeRefreshToken(refreshToken);

            String accessToken = logoutRequest.accessToken();
            tokenAuthenticationService.addBlackList(accessToken);
        } catch (IOException e) {
            throw new CustomException(INVALID_REQUEST);
        }
    }
}
