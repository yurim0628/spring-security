package com.example.springsecurity.security;

import com.example.springsecurity.security.login.AuthenticationService;
import com.example.springsecurity.user.model.User;
import com.example.springsecurity.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import static com.example.springsecurity.common.exception.ErrorCode.INVALID_CREDENTIALS;

@Service
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService {

    private final AuthenticationService authenticationService;
    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException(INVALID_CREDENTIALS.getMessage()));
        if (!user.isAccountNonLocked()) authenticationService.checkAndSetAccountUnlocked(user);
        return new PrincipalDetails(user);
    }
}
