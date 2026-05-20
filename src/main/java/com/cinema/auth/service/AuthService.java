package com.cinema.auth.service;

import com.cinema.auth.dto.LoginRequest;
import com.cinema.auth.dto.LoginResponse;
import com.cinema.auth.dto.MeResponse;
import com.cinema.auth.dto.RegisterRequest;

import java.util.UUID;

public interface AuthService {

    LoginResponse register(RegisterRequest request);

    LoginResponse login(LoginRequest request);

    MeResponse getCurrentUser(String authorizationHeader);

    void deactivateUser(UUID userId);
}
