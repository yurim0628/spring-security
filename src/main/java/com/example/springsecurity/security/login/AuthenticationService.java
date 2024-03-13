package com.example.springsecurity.security.login;

import com.example.springsecurity.user.model.User;
import com.example.springsecurity.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

import static com.example.springsecurity.security.common.SecurityConstants.*;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository userRepository;

    @Transactional
    public void increaseFailedLoginAttempts(User user) {
        int failedLoginAttempts = user.getFailedLoginAttempts() + DEFAULT_LOGIN_ATTEMPT_INCREMENT;
        user.setFailedLoginAttempts(failedLoginAttempts);
        userRepository.save(user);
        log.info("increased failed login attempts for user with email: {}", user.getEmail());
    }

    @Transactional
    public void resetFailedLoginAttempts(User user) {
        user.setFailedLoginAttempts(MIN_FAILED_LOGIN_ATTEMPTS);
        userRepository.save(user);
        log.info("reset failed login attempts for user with email: {}", user.getEmail());
    }

    @Transactional
    public void setAccountLocked(User user) {
        LocalDateTime currentDateTime = LocalDateTime.now();
        LocalDateTime lockExpiration = currentDateTime.plusDays(LOCK_DURATION_DAYS);
        user.setLockExpiration(lockExpiration);
        userRepository.save(user);
        log.info("set account locked for user with email: {}", user.getEmail());
    }
}
