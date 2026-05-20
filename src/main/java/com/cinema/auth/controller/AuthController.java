package com.cinema.auth.controller;

import com.cinema.auth.constants.AuthConstants;
import com.cinema.auth.dto.LoginRequest;
import com.cinema.auth.dto.LoginResponse;
import com.cinema.auth.dto.MeResponse;
import com.cinema.auth.dto.RegisterRequest;
import com.cinema.auth.service.AuthService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

@RestController
@RequestMapping(AuthConstants.AUTH_BASE_PATH)
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping(AuthConstants.AUTH_REGISTER_PATH)
    public ResponseEntity<LoginResponse> register(@Valid @RequestBody RegisterRequest request) {
        return ResponseEntity.ok(authService.register(request));
    }

    @PostMapping(AuthConstants.AUTH_LOGIN_PATH)
    public ResponseEntity<LoginResponse> login(@Valid @RequestBody LoginRequest request) {
        return ResponseEntity.ok(authService.login(request));
    }

    @GetMapping(AuthConstants.AUTH_ME_PATH)
    public ResponseEntity<MeResponse> me(@RequestHeader(AuthConstants.AUTHORIZATION_HEADER) String authorization) {
        return ResponseEntity.ok(authService.getCurrentUser(authorization));
    }

    @PatchMapping(AuthConstants.AUTH_DEACTIVATE_PATH)
    public ResponseEntity<Void> deactivate(@PathVariable UUID id) {
        authService.deactivateUser(id);
        return ResponseEntity.noContent().build();
    }
}
