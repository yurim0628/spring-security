package com.example.springsecurity.common.exception;

import com.example.springsecurity.common.response.Response;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@Slf4j
@RestControllerAdvice
public class CommonExceptionHandler {

    @ExceptionHandler(value = CustomException.class)
    public ResponseEntity<Response<Void>> handleCustomException(
            CustomException e,
            HttpServletRequest request
    ) {
        HttpStatus status = e.getErrorCode().getStatus();
        String message = e.getErrorCode().getMessage();
        String url = request.getRequestURI();

        log.error("Custom Exception - status: {}, message: {}, url: {}",
                status,
                message,
                url
        );

        return new ResponseEntity<>(
                Response.fail(message),
                status
        );
    }
}
