package com.cinema.auth.controller;

import com.cinema.auth.constants.AuthConstants;
import com.cinema.auth.dto.AdminCreateUserRequest;
import com.cinema.auth.dto.AdminCreateUserResponse;
import com.cinema.auth.dto.AuthUserSummaryResponse;
import com.cinema.auth.dto.ChangePasswordRequest;
import com.cinema.auth.dto.ForgotPasswordRequest;
import com.cinema.auth.dto.LoginRequest;
import com.cinema.auth.dto.LoginResponse;
import com.cinema.auth.dto.MeResponse;
import com.cinema.auth.dto.RegisterRequest;
import com.cinema.auth.dto.ResetPasswordRequest;
import com.cinema.auth.service.AuthService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
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

    @PostMapping(AuthConstants.AUTH_LOGOUT_PATH)
    public ResponseEntity<Void> logout(@RequestHeader(AuthConstants.AUTHORIZATION_HEADER) String authorization) {
        authService.logout(authorization);
        return ResponseEntity.noContent().build();
    }

    @PostMapping(AuthConstants.AUTH_FORGOT_PASSWORD_PATH)
    public ResponseEntity<Void> forgotPassword(@Valid @RequestBody ForgotPasswordRequest request) {
        authService.requestPasswordRecovery(request);
        return ResponseEntity.accepted().build();
    }

    @PostMapping(AuthConstants.AUTH_RESET_PASSWORD_PATH)
    public ResponseEntity<Void> resetPassword(@Valid @RequestBody ResetPasswordRequest request) {
        authService.resetPassword(request);
        return ResponseEntity.noContent().build();
    }

    @PostMapping(AuthConstants.AUTH_CHANGE_PASSWORD_PATH)
    public ResponseEntity<Void> changePassword(
            @RequestHeader(AuthConstants.AUTHORIZATION_HEADER) String authorization,
            @Valid @RequestBody ChangePasswordRequest request
    ) {
        authService.changePassword(authorization, request);
        return ResponseEntity.noContent().build();
    }

    @PatchMapping(AuthConstants.AUTH_DEACTIVATE_PATH)
    public ResponseEntity<Void> deactivate(@PathVariable UUID id) {
        authService.deactivateUser(id);
        return ResponseEntity.noContent().build();
    }

    @PatchMapping(AuthConstants.AUTH_ACTIVATE_PATH)
    public ResponseEntity<Void> activate(@PathVariable UUID id) {
        authService.activateUser(id);
        return ResponseEntity.noContent().build();
    }

    @GetMapping(AuthConstants.AUTH_EXISTS_ADMIN_PATH)
    public ResponseEntity<Boolean> existsAdmin(
            @RequestHeader(value = AuthConstants.INTERNAL_SERVICE_HEADER, required = false) String internalHeader
    ) {
        validateInternalHeader(internalHeader);
        return ResponseEntity.ok(authService.existsSystemAdmin());
    }

    @PostMapping(AuthConstants.AUTH_ADMIN_CREATE_USER_PATH)
    public ResponseEntity<AdminCreateUserResponse> createUserByAdmin(
            @RequestHeader(value = AuthConstants.INTERNAL_SERVICE_HEADER, required = false) String internalHeader,
            @Valid @RequestBody AdminCreateUserRequest request
    ) {
        validateInternalHeader(internalHeader);
        return ResponseEntity.status(HttpStatus.CREATED).body(authService.createUserByAdmin(request));
    }

    @GetMapping(AuthConstants.AUTH_ADMIN_LIST_PATH)
    public ResponseEntity<List<AuthUserSummaryResponse>> listUsers(
            @RequestHeader(value = AuthConstants.INTERNAL_SERVICE_HEADER, required = false) String internalHeader
    ) {
        validateInternalHeader(internalHeader);
        return ResponseEntity.ok(authService.listUsers());
    }

    @PatchMapping(AuthConstants.AUTH_ADMIN_DEACTIVATE_PATH)
    public ResponseEntity<Void> adminDeactivate(
            @RequestHeader(value = AuthConstants.INTERNAL_SERVICE_HEADER, required = false) String internalHeader,
            @PathVariable UUID id
    ) {
        validateInternalHeader(internalHeader);
        authService.deactivateUser(id);
        return ResponseEntity.noContent().build();
    }

    @PatchMapping(AuthConstants.AUTH_ADMIN_ACTIVATE_PATH)
    public ResponseEntity<Void> adminActivate(
            @RequestHeader(value = AuthConstants.INTERNAL_SERVICE_HEADER, required = false) String internalHeader,
            @PathVariable UUID id
    ) {
        validateInternalHeader(internalHeader);
        authService.activateUser(id);
        return ResponseEntity.noContent().build();
    }

    private void validateInternalHeader(String internalHeader) {
        if (!AuthConstants.INTERNAL_SERVICE_HEADER_VALUE.equalsIgnoreCase(String.valueOf(internalHeader))) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Acceso interno requerido");
        }
    }
}