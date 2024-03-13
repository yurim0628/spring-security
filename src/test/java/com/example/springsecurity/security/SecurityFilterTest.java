package com.example.springsecurity.security;

import com.example.springsecurity.common.WithMockCustomUser;
import com.example.springsecurity.common.redis.RedisService;
import com.example.springsecurity.security.authentication.TokenAuthenticationService;
import com.example.springsecurity.security.login.LoginRequest;
import com.example.springsecurity.security.logout.LogoutRequest;
import com.example.springsecurity.security.reissue.ReissueRequest;
import com.example.springsecurity.user.model.User;
import com.example.springsecurity.user.repository.UserRepository;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

import static com.example.springsecurity.security.common.SecurityConstants.REFRESH_TOKEN_PREFIX;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@Transactional
public class SecurityFilterTest {

    @Autowired
    private MockMvc mvc;

    @Autowired
    ObjectMapper objectMapper;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Autowired
    UserRepository userRepository;

    @Autowired
    TokenAuthenticationService tokenAuthenticationService;

    @Autowired
    RedisService redisService;

    private static final String LOGIN_ENDPOINT = "/login";
    private static final String LOGOUT_ENDPOINT = "/logout";
    private static final String REISSUE_ENDPOINT = "/reissue";
    private static final String VALID_EMAIL = "valid@email.com";
    private static final String INVALID_EMAIL = "invalid@email.com";
    private static final String VALID_PASSWORD = "valid";
    private static final String INVALID_PASSWORD = "invalid";
    private static final int FAILED_LOGIN_ATTEMPTS = 5;

    @Test
    @DisplayName("로그인_성공")
    public void loginSuccess() throws Exception {
        // given
        createUser();
        String requestBodyJson = createLoginRequestBody(VALID_EMAIL, VALID_PASSWORD);

        // when
        ResultActions resultActions = performPostRequest(LOGIN_ENDPOINT, requestBodyJson);

        // then
        resultActions.andExpect(status().isOk());
    }

    @Test
    @DisplayName("로그인_실패_이메일_불일치")
    public void loginFail() throws Exception {
        // given
        createLockedUser();
        String requestBodyJson = createLoginRequestBody(INVALID_EMAIL, VALID_PASSWORD);

        // when
        ResultActions resultActions = performPostRequest(LOGIN_ENDPOINT, requestBodyJson);

        // then
        resultActions.andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("로그인_실패_잠금_계정")
    public void loginFailWithLockedAccount() throws Exception {
        // given
        createLockedUser();
        String requestBodyJson = createLoginRequestBody(VALID_EMAIL, INVALID_PASSWORD);

        // when
        ResultActions resultActions = performPostRequest(LOGIN_ENDPOINT, requestBodyJson);

        // then
        resultActions.andExpect(status().isLocked());
    }

    @Test
    @WithMockCustomUser
    @DisplayName("로그아웃")
    public void logout() throws Exception {
        // given
        String uuid = UUID.randomUUID().toString();
        Token token = createToken(uuid);
        String requestBodyJson = createLogoutRequestBody(token.accessToken(), token.refreshToken());

        // when
        ResultActions resultActions = performPostRequest(LOGOUT_ENDPOINT, requestBodyJson);

        // then
        resultActions
                .andExpect(status().isOk())
                .andReturn();
        assert redisService.get(REFRESH_TOKEN_PREFIX + uuid, RefreshToken.class).isEmpty();
        assert tokenAuthenticationService.isBlackListToken(token.accessToken());
    }

    @Test
    @WithMockCustomUser
    @DisplayName("토큰_재발급")
    public void reissue() throws Exception {
        // given
        String uuid = UUID.randomUUID().toString();
        Token token = createToken(uuid);
        String requestBodyJson = createReissueRequestBody(token.refreshToken());

        // when
        ResultActions resultActions = performPostRequest(REISSUE_ENDPOINT, requestBodyJson);

        resultActions.andExpect(status().isOk());
    }

    @Transactional
    private void createUser() {
        User user = buildUser();
        userRepository.save(user);
    }

    @Transactional
    private void createLockedUser() {
        User user = buildUser();
        user.setFailedLoginAttempts(FAILED_LOGIN_ATTEMPTS);
        userRepository.save(user);
    }

    private User buildUser() {
        String encodedPassword = passwordEncoder.encode(VALID_PASSWORD);
        return User.builder()
                .email(VALID_EMAIL)
                .password(encodedPassword)
                .build();
    }

    private Token createToken(String uuid) {
        SecurityContext securityContext = SecurityContextHolder.getContext();
        PrincipalDetails userDetails = (PrincipalDetails) securityContext.getAuthentication().getPrincipal();

        return tokenAuthenticationService.createToken(
                userDetails.getUsername(),
                userDetails.getAuthorities().toString(),
                uuid
        );
    }

    private String createLoginRequestBody(String email, String password) throws JsonProcessingException {
        LoginRequest loginRequest = new LoginRequest(email, password);
        return objectMapper.writeValueAsString(loginRequest);
    }

    private String createLogoutRequestBody(String accessToken, String refreshToken) throws JsonProcessingException {
        LogoutRequest logoutRequest = new LogoutRequest(accessToken, refreshToken);
        return objectMapper.writeValueAsString(logoutRequest);
    }

    private String createReissueRequestBody(String refreshToken) throws JsonProcessingException {
        ReissueRequest reissueRequest = new ReissueRequest(refreshToken);
        return objectMapper.writeValueAsString(reissueRequest);
    }

    private ResultActions performPostRequest(String endpoint, String requestBodyJson) throws Exception {
        return mvc.perform(
                post(endpoint)
                        .content(requestBodyJson)
                        .contentType(APPLICATION_JSON)
                        .accept(APPLICATION_JSON)
        ).andDo(print());
    }
}
