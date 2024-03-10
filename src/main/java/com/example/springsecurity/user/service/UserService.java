package com.example.springsecurity.user.service;

import com.example.springsecurity.common.exception.CustomException;
import com.example.springsecurity.security.common.SecurityUtil;
import com.example.springsecurity.user.dto.request.RegisterRequest;
import com.example.springsecurity.user.dto.response.RegisterResponse;
import com.example.springsecurity.user.model.User;
import com.example.springsecurity.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import static com.example.springsecurity.common.exception.ErrorCode.EMAIL_ALREADY_EXISTS;
import static com.example.springsecurity.common.exception.ErrorCode.USER_NOT_FOUND;
import static com.example.springsecurity.security.common.SecurityConstants.ACCOUNT_ENABLED_STATUS;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserService {

    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;

    @Transactional
    public RegisterResponse register(RegisterRequest registerRequest) {
        if (userRepository.existsByEmail(registerRequest.email())){
            throw new CustomException(EMAIL_ALREADY_EXISTS);
        }

        String encodedPassword = passwordEncoder.encode(registerRequest.password());
        User user = registerRequest.of(encodedPassword);
        userRepository.save(user);

        return RegisterResponse.from(user);
    }

    @Transactional
    public void unregister() {
        Long userId = SecurityUtil.getUserId();
        User user = userRepository.getUserById(userId).orElseThrow(() -> new CustomException(USER_NOT_FOUND));
        user.setEnabled(ACCOUNT_ENABLED_STATUS);
        userRepository.save(user);
    }
}
