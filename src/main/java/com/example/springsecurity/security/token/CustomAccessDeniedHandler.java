package com.example.springsecurity.security.token;

import com.example.springsecurity.common.response.Response;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;

import java.io.IOException;

import static com.example.springsecurity.common.exception.ErrorCode.ACCESS_DENIED;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@RequiredArgsConstructor
public class CustomAccessDeniedHandler implements AccessDeniedHandler {

    private final ObjectMapper objectMapper;

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response,
                       AccessDeniedException accessDeniedException) throws IOException {
        String errorMessage = ACCESS_DENIED.getMessage();
        sendResponse(response, errorMessage);
    }

    private void sendResponse(HttpServletResponse response, String errorMessage)
            throws IOException {
        response.setContentType(APPLICATION_JSON_VALUE);
        response.setCharacterEncoding(UTF_8.name());
        response.setStatus(FORBIDDEN.value());
        objectMapper.writeValue(
                response.getWriter(),
                Response.fail(errorMessage)
        );
    }
}
