package com.example.springsecurity.user.controller;

import com.example.springsecurity.common.response.Response;
import com.example.springsecurity.user.dto.RegisterRequest;
import com.example.springsecurity.user.dto.RegisterResponse;
import com.example.springsecurity.user.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

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
