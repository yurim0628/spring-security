package com.example.springsecurity.security.login;

import com.example.springsecurity.common.response.Response;
import com.example.springsecurity.security.PrincipalDetails;
import com.example.springsecurity.security.jwt.JwtService;
import com.example.springsecurity.security.Token;
import com.example.springsecurity.user.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.io.IOException;
import java.util.UUID;

import static com.example.springsecurity.security.common.SecurityConstants.MIN_FAILED_LOGIN_ATTEMPTS;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;
import static java.nio.charset.StandardCharsets.UTF_8;

@RequiredArgsConstructor
public class CustomAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private final ObjectMapper objectMapper;
    private final JwtService jwtService;
    private final AuthenticationService authenticationService;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException {
        PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();

        User user = principalDetails.user();
        if(user.getFailedLoginAttempts() > MIN_FAILED_LOGIN_ATTEMPTS) {
            authenticationService.resetFailedLoginAttempts(user);
        }

        Token token = jwtService.createToken(
                principalDetails.getUsername(),
                principalDetails.getAuthorities().toString(),
                generateRefreshTokenUUID()
        );
        sendSuccessResponse(response, LoginResponse.from(token));
    }

    private String generateRefreshTokenUUID() {
        return UUID.randomUUID().toString();
    }

    private void sendSuccessResponse(HttpServletResponse response, LoginResponse loginResponse)
            throws IOException {
        response.setContentType(APPLICATION_JSON_VALUE);
        response.setCharacterEncoding(UTF_8.name());
        response.setStatus(HttpStatus.OK.value());
        objectMapper.writeValue(
                response.getWriter(),
                Response.success(loginResponse)
        );
    }
}
