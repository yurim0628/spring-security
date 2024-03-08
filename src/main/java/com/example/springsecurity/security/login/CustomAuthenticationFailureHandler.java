package com.example.springsecurity.security.login;

import com.example.springsecurity.common.exception.ErrorCode;
import com.example.springsecurity.common.redis.RedisService;
import com.example.springsecurity.common.response.Response;
import com.example.springsecurity.user.model.User;
import com.example.springsecurity.user.repository.UserRepository;
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
    private final RedisService redisService;
    private final UserRepository userRepository;

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException exception) throws IOException {
        LoginRequest loginRequest = (LoginRequest) request.getAttribute(LOGIN_REQUEST_ATTRIBUTE);
        ErrorCode error;
        if (exception instanceof BadCredentialsException) {
            error = handleBadCredentials(loginRequest);
        } else if (exception instanceof LockedException) {
            error = handleLocked(loginRequest);
        } else if (exception instanceof InternalAuthenticationServiceException) {
            error = INTERNAL_AUTHENTICATION_ERROR;
        } else {
            error = UNKNOWN_ERROR;
        }
        sendFailResponse(response, error);
    }

    private ErrorCode handleBadCredentials(LoginRequest loginRequest) {
        Optional<User> userOptional = userRepository.findByEmail(loginRequest.email());

        if (userOptional.isPresent()) {
            User user = userOptional.get();
            user.increaseFailedLoginAttempts();

            if (user.getFailedLoginAttempts() >= MAX_FAILED_LOGIN_ATTEMPTS) {
                user.setAccountNonLocked(false);
                redisService.set(
                        ACCOUNT_LOCKED_PREFIX + user.getEmail(),
                        ACCOUNT_LOCKED_STATUS,
                        ACCOUNT_LOCK_EXPIRATION
                );
                userRepository.save(user);
                return LOCKED_ACCOUNT;
            }

            userRepository.save(user);
            return INVALID_CREDENTIALS;
        }

        return INVALID_CREDENTIALS;
    }

    private ErrorCode handleLocked(LoginRequest loginRequest) {
        User user = userRepository.findByEmail(loginRequest.email()).get();

        boolean isAccountLocked = redisService.get(
                ACCOUNT_LOCKED_PREFIX + user.getEmail(),
                String.class
        ).isPresent();
        if (!isAccountLocked) {
            user.resetFailedLoginAttempts();
            user.setAccountNonLocked(true);

            userRepository.save(user);
            return INVALID_CREDENTIALS;
        }

        return LOCKED_ACCOUNT;
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
