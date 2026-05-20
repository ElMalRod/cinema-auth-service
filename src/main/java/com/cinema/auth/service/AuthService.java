package com.cinema.auth.service;

import com.cinema.auth.dto.ChangePasswordRequest;
import com.cinema.auth.dto.ForgotPasswordRequest;
import com.cinema.auth.dto.LoginRequest;
import com.cinema.auth.dto.LoginResponse;
import com.cinema.auth.dto.MeResponse;
import com.cinema.auth.dto.RegisterRequest;
import com.cinema.auth.dto.ResetPasswordRequest;

import java.util.UUID;

public interface AuthService {

    LoginResponse register(RegisterRequest request);

    LoginResponse login(LoginRequest request);

    MeResponse getCurrentUser(String authorizationHeader);

    void logout(String authorizationHeader);

    void requestPasswordRecovery(ForgotPasswordRequest request);

    void resetPassword(ResetPasswordRequest request);

    void changePassword(String authorizationHeader, ChangePasswordRequest request);

    void deactivateUser(UUID userId);
}
