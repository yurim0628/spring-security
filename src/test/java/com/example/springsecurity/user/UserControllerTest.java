package com.example.springsecurity.user;

import com.example.springsecurity.common.WithMockCustomUser;
import com.example.springsecurity.common.response.Response;
import com.example.springsecurity.user.dto.request.RegisterRequest;
import com.example.springsecurity.user.dto.response.RegisterResponse;
import com.example.springsecurity.user.model.User;
import com.example.springsecurity.user.repository.UserRepository;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
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
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.junit.jupiter.api.Assertions.assertEquals;

@SpringBootTest
@AutoConfigureMockMvc
@Transactional
public class UserControllerTest {

    @Autowired
    private MockMvc mvc;

    @Autowired
    ObjectMapper objectMapper;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Autowired
    UserRepository userRepository;

    User user;
    @BeforeEach
    void setUp() {
        String email = "user@email.com";
        String encodedPassword = passwordEncoder.encode("1234");
        user = User.builder()
                .email(email)
                .password(encodedPassword)
                .build();
        userRepository.save(user);
    }

    @AfterEach
    void tearDown() {
        userRepository.deleteAll();
    }

    @Test
    @DisplayName("회원_가입_성공")
    public void registerSuccess() throws Exception {
        // given
        RegisterRequest registerRequest = new RegisterRequest("test@email.com", "1234");
        String requestBodyJson = objectMapper.writeValueAsString(registerRequest);

        // when
        ResultActions resultActions = mvc.perform(post("/users/register")
                        .content(requestBodyJson)
                        .contentType(APPLICATION_JSON)
                        .accept(APPLICATION_JSON)
                )
                .andDo(print());

        // then
        resultActions.andExpect(status().isOk())
                .andDo(result -> {
                    String responseBodyJson = result.getResponse().getContentAsString();
                    Response<RegisterResponse> response = objectMapper.readValue(responseBodyJson, new TypeReference<>() {});
                    RegisterResponse registerResponse = objectMapper.convertValue(response.data(), RegisterResponse.class);
                    assertEquals(2L, registerResponse.id());
                    assertEquals("test@email.com", registerResponse.email());
                });
    }

    @Test
    @DisplayName("회원_가입_실패_중복_이메일")
    public void registerFail() throws Exception {
        // given
        RegisterRequest registerRequest = new RegisterRequest("user@email.com", "1234");
        String requestBodyJson = objectMapper.writeValueAsString(registerRequest);

        // when
        ResultActions resultActions = mvc.perform(post("/users/register")
                        .content(requestBodyJson)
                        .contentType(APPLICATION_JSON)
                        .accept(APPLICATION_JSON)
                )
                .andDo(print());

        // then
        resultActions.andExpect(status().isConflict());
    }

    @Test
    @WithMockCustomUser
    @DisplayName("회원_탈퇴_성공")
    public void unregisterSuccess() throws Exception {
        // given
        // when
        ResultActions resultActions = mvc.perform(delete("/users/unregister")
                        .accept(APPLICATION_JSON))
                .andDo(print());

        // then
        resultActions.andExpect(status().isOk());
    }
}
