package com.example.springsecurity.security.login;

import com.example.springsecurity.common.redis.RedisService;
import com.example.springsecurity.user.model.User;
import com.example.springsecurity.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

import static com.example.springsecurity.security.SecurityConstants.*;

@Slf4j
@Component
@RequiredArgsConstructor
public class AuthenticationService {

    private final RedisService redisService;
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
        user.setAccountNonLocked(!ACCOUNT_UNLOCKED_STATUS);
        redisService.set(
                ACCOUNT_LOCKED_PREFIX + user.getEmail(),
                ACCOUNT_LOCKED_STATUS,
                ACCOUNT_LOCK_EXPIRATION
        );
        userRepository.save(user);
        log.info("set account locked for user with email: {}", user.getEmail());
    }

    @Transactional
    public void checkAndSetAccountUnlocked(User user) {
        boolean isAccountLocked
                = redisService.get(ACCOUNT_LOCKED_PREFIX + user.getEmail(), String.class).isPresent();
        if (!isAccountLocked) {
            user.setFailedLoginAttempts(MIN_FAILED_LOGIN_ATTEMPTS);
            user.setAccountNonLocked(ACCOUNT_UNLOCKED_STATUS);
            userRepository.save(user);
            log.info("checked and set account unlocked for user with email: {}", user.getEmail());
        }
    }

    public Optional<User> findByEmail(String email) {
        return userRepository.findByEmail(email);
    }
}
