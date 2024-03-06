package com.example.springsecurity.user.controller;

import com.example.springsecurity.common.response.Response;
import com.example.springsecurity.user.dto.request.RegisterRequest;
import com.example.springsecurity.user.dto.response.RegisterResponse;
import com.example.springsecurity.user.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @PostMapping("/register")
    public ResponseEntity<Response<RegisterResponse>> register(@RequestBody RegisterRequest registerRequest) {
        return ResponseEntity.ok(Response.success(userService.register(registerRequest)));
    }
}
