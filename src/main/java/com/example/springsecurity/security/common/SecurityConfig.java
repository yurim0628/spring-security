package com.example.springsecurity.security.common;

import com.example.springsecurity.security.jwt.CustomAccessDeniedHandler;
import com.example.springsecurity.security.jwt.CustomAuthenticationEntryPoint;
import com.example.springsecurity.security.jwt.JwtAuthenticationConfig;
import com.example.springsecurity.security.jwt.JwtService;
import com.example.springsecurity.security.login.AuthenticationService;
import com.example.springsecurity.security.login.CustomAuthenticationConfig;
import com.example.springsecurity.security.logout.CustomLogoutHandler;
import com.example.springsecurity.security.logout.CustomLogoutSuccessHandler;
import com.example.springsecurity.user.repository.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    private final ObjectMapper objectMapper;
    private final JwtService jwtService;
    private final AuthenticationService authenticationService;
    private final UserRepository userRepository;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .headers(headers -> headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin))
                .authorizeHttpRequests(authorizeRequests->
                        authorizeRequests
                                .requestMatchers("/users/**").permitAll()
                                .anyRequest().authenticated()
                )
                .sessionManagement((sessionManagement) -> sessionManagement
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .with(
                        customAuthenticationConfig(),
                        Customizer.withDefaults()
                )
                .with(
                        jwtAuthenticationConfig(),
                        Customizer.withDefaults()
                )
                .exceptionHandling(exceptionHandling ->
                        exceptionHandling
                                .authenticationEntryPoint(customAuthenticationEntryPoint())
                                .accessDeniedHandler(customAccessDeniedHandler())
                )
                .logout(logoutConfigurer ->
                        logoutConfigurer
                                .addLogoutHandler(customLogoutHandler())
                                .logoutSuccessHandler(customLogoutSuccessHandler())
                );

        return http.build();
    }

    private CustomAuthenticationConfig customAuthenticationConfig() {
        return new CustomAuthenticationConfig(objectMapper, jwtService, authenticationService, userRepository);
    }

    private JwtAuthenticationConfig jwtAuthenticationConfig() {
        return new JwtAuthenticationConfig(objectMapper, jwtService);
    }

    private CustomAuthenticationEntryPoint customAuthenticationEntryPoint() {
        return new CustomAuthenticationEntryPoint(objectMapper);
    }

    private CustomAccessDeniedHandler customAccessDeniedHandler() {
        return new CustomAccessDeniedHandler(objectMapper);
    }

    private CustomLogoutHandler customLogoutHandler() {
        return new CustomLogoutHandler(objectMapper, jwtService);
    }

    private LogoutSuccessHandler customLogoutSuccessHandler() {
        return new CustomLogoutSuccessHandler(objectMapper);
    }
}
