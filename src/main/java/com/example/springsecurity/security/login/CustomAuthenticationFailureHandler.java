package com.example.springsecurity.security.login;

import com.example.springsecurity.common.exception.ErrorCode;
import com.example.springsecurity.common.response.Response;
import com.example.springsecurity.user.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import java.io.IOException;
import java.util.Optional;

import static com.example.springsecurity.common.exception.ErrorCode.*;
import static com.example.springsecurity.security.SecurityConstants.*;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@RequiredArgsConstructor
public class CustomAuthenticationFailureHandler implements AuthenticationFailureHandler {

    private final ObjectMapper objectMapper;
    private final AuthenticationService authenticationService;

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException exception) throws IOException {
        ErrorCode error;
        if (exception instanceof BadCredentialsException) {
            error = handleBadCredentials(request);
        } else if (exception instanceof LockedException) {
            error = LOCKED_ACCOUNT;
        } else if (exception instanceof InternalAuthenticationServiceException) {
            error = INTERNAL_AUTHENTICATION_ERROR;
        } else {
            error = UNKNOWN_ERROR;
        }
        sendFailResponse(response, error);
    }

    private ErrorCode handleBadCredentials(HttpServletRequest request) {
        String email = (String) request.getAttribute(EMAIL_ATTRIBUTE);
        Optional<User> userOptional = authenticationService.findByEmail(email);

        if (userOptional.isPresent()) {
            User user = userOptional.get();
            authenticationService.increaseFailedLoginAttempts(user);

            int failedLoginAttempts = user.getFailedLoginAttempts();
            if (failedLoginAttempts >= MAX_FAILED_LOGIN_ATTEMPTS) {
                authenticationService.setAccountLocked(user);
                return LOCKED_ACCOUNT;
            }

            return INVALID_CREDENTIALS;
        }

        return INVALID_CREDENTIALS;
    }

    private void sendFailResponse(HttpServletResponse response, ErrorCode errorCode)
            throws IOException {
        response.setContentType(APPLICATION_JSON_VALUE);
        response.setCharacterEncoding(UTF_8.name());
        response.setStatus(errorCode.getStatus().value());
        objectMapper.writeValue(
                response.getWriter(),
                Response.fail(errorCode.getMessage())
        );
    }
}
