package com.example.springsecurity.security;

import com.example.springsecurity.security.login.LoginRequest;
import com.example.springsecurity.user.model.User;
import com.example.springsecurity.user.repository.UserRepository;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.transaction.annotation.Transactional;

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

    private static final String LOGIN_ENDPOINT = "/login";
    private static final String VALID_EMAIL = "valid@email.com";
    private static final String INVALID_EMAIL = "invalid@email.com";
    private static final String VALID_PASSWORD = "valid";
    private static final String INVALID_PASSWORD = "invalid";
    private static final int FAILED_LOGIN_ATTEMPTS = 5;
    private static final boolean ACCOUNT_ENABLED_STATUS = false;

    @Test
    @DisplayName("로그인_성공")
    public void loginSuccess() throws Exception {
        // given
        createUser();
        String requestBodyJson = createLoginRequestBody(VALID_EMAIL, VALID_PASSWORD);

        // when
        ResultActions resultActions = performLogin(requestBodyJson);

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
        ResultActions resultActions = performLogin(requestBodyJson);

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
        ResultActions resultActions = performLogin(requestBodyJson);

        // then
        resultActions.andExpect(status().isLocked());
    }

    private ResultActions performLogin(String requestBodyJson) throws Exception {
        return mvc.perform(
                post(LOGIN_ENDPOINT)
                        .content(requestBodyJson)
                        .contentType(APPLICATION_JSON)
                        .accept(APPLICATION_JSON)
        ).andDo(print());
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

    private String createLoginRequestBody(String email, String password) throws JsonProcessingException {
        LoginRequest loginRequest = new LoginRequest(email, password);
        return objectMapper.writeValueAsString(loginRequest);
    }
}
