package com.cinema.auth.controller;

import com.cinema.auth.domain.UserRole;
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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthControllerUnitTest {

    private static final String AUTHORIZATION_HEADER = "Bearer token";
    private static final String INTERNAL_HEADER = "true";
    private static final String INVALID_INTERNAL_HEADER = "false";
    private static final UUID USER_ID = UUID.fromString("00000000-0000-0000-0000-000000000701");
    private static final String USER_EMAIL = "user@test.com";
    private static final String PASSWORD = "password123";
    private static final String NEW_PASSWORD = "new-password123";
    private static final String TOKEN = "jwt-token";

    @Mock
    private AuthService authService;

    private AuthController authController;

    @BeforeEach
    void setUp() {
        authController = new AuthController(authService);
    }

    @Test
    void should_ReturnLoginResponse_When_RegisterIsCalled() {
        // Arrange
        RegisterRequest request = new RegisterRequest(USER_EMAIL, PASSWORD, UserRole.CLIENT);
        LoginResponse response = new LoginResponse(TOKEN, USER_ID, USER_EMAIL, UserRole.CLIENT.name());
        when(authService.register(request)).thenReturn(response);

        // Act
        var result = authController.register(request);

        // Assert
        assertEquals(HttpStatus.OK, result.getStatusCode());
        assertEquals(TOKEN, result.getBody().token());
    }

    @Test
    void should_ReturnLoginResponse_When_LoginIsCalled() {
        // Arrange
        LoginRequest request = new LoginRequest(USER_EMAIL, PASSWORD);
        LoginResponse response = new LoginResponse(TOKEN, USER_ID, USER_EMAIL, UserRole.CLIENT.name());
        when(authService.login(request)).thenReturn(response);

        // Act
        var result = authController.login(request);

        // Assert
        assertEquals(HttpStatus.OK, result.getStatusCode());
        assertEquals(USER_EMAIL, result.getBody().email());
    }

    @Test
    void should_ReturnCurrentUser_When_MeIsCalled() {
        // Arrange
        MeResponse meResponse = new MeResponse(USER_ID, USER_EMAIL, UserRole.CLIENT.name(), true);
        when(authService.getCurrentUser(AUTHORIZATION_HEADER)).thenReturn(meResponse);

        // Act
        var result = authController.me(AUTHORIZATION_HEADER);

        // Assert
        assertEquals(HttpStatus.OK, result.getStatusCode());
        assertEquals(USER_ID, result.getBody().userId());
    }

    @Test
    void should_ReturnNoContent_When_LogoutIsCalled() {
        // Arrange

        // Act
        var result = authController.logout(AUTHORIZATION_HEADER);

        // Assert
        assertEquals(HttpStatus.NO_CONTENT, result.getStatusCode());
        verify(authService).logout(AUTHORIZATION_HEADER);
    }

    @Test
    void should_ReturnAccepted_When_ForgotPasswordIsCalled() {
        // Arrange
        ForgotPasswordRequest request = new ForgotPasswordRequest(USER_EMAIL);

        // Act
        var result = authController.forgotPassword(request);

        // Assert
        assertEquals(HttpStatus.ACCEPTED, result.getStatusCode());
        verify(authService).requestPasswordRecovery(request);
    }

    @Test
    void should_ReturnNoContent_When_ResetPasswordIsCalled() {
        // Arrange
        ResetPasswordRequest request = new ResetPasswordRequest("plain-token", NEW_PASSWORD);

        // Act
        var result = authController.resetPassword(request);

        // Assert
        assertEquals(HttpStatus.NO_CONTENT, result.getStatusCode());
        verify(authService).resetPassword(request);
    }

    @Test
    void should_ReturnNoContent_When_ChangePasswordIsCalled() {
        // Arrange
        ChangePasswordRequest request = new ChangePasswordRequest(PASSWORD, NEW_PASSWORD);

        // Act
        var result = authController.changePassword(AUTHORIZATION_HEADER, request);

        // Assert
        assertEquals(HttpStatus.NO_CONTENT, result.getStatusCode());
        verify(authService).changePassword(AUTHORIZATION_HEADER, request);
    }

    @Test
    void should_ReturnNoContent_When_DeactivateIsCalled() {
        // Arrange

        // Act
        var result = authController.deactivate(USER_ID);

        // Assert
        assertEquals(HttpStatus.NO_CONTENT, result.getStatusCode());
        verify(authService).deactivateUser(USER_ID);
    }

    @Test
    void should_ReturnNoContent_When_ActivateIsCalled() {
        // Arrange

        // Act
        var result = authController.activate(USER_ID);

        // Assert
        assertEquals(HttpStatus.NO_CONTENT, result.getStatusCode());
        verify(authService).activateUser(USER_ID);
    }

    @Test
    void should_ReturnExistsAdmin_When_InternalHeaderIsValid() {
        // Arrange
        when(authService.existsSystemAdmin()).thenReturn(true);

        // Act
        var result = authController.existsAdmin(INTERNAL_HEADER);

        // Assert
        assertEquals(HttpStatus.OK, result.getStatusCode());
        assertEquals(true, result.getBody());
    }

    @Test
    void should_ThrowForbidden_When_ExistsAdminHeaderIsInvalid() {
        // Arrange

        // Act
        ResponseStatusException exception = assertThrows(ResponseStatusException.class, () -> authController.existsAdmin(INVALID_INTERNAL_HEADER));

        // Assert
        assertEquals(HttpStatus.FORBIDDEN, exception.getStatusCode());
    }

    @Test
    void should_CreateUserByAdmin_When_InternalHeaderIsValid() {
        // Arrange
        AdminCreateUserRequest request = new AdminCreateUserRequest(USER_EMAIL, PASSWORD, UserRole.CLIENT, true);
        AdminCreateUserResponse response = new AdminCreateUserResponse(USER_ID, USER_EMAIL, UserRole.CLIENT.name(), true, true);
        when(authService.createUserByAdmin(request)).thenReturn(response);

        // Act
        var result = authController.createUserByAdmin(INTERNAL_HEADER, request);

        // Assert
        assertEquals(HttpStatus.CREATED, result.getStatusCode());
        assertEquals(USER_ID, result.getBody().id());
    }

    @Test
    void should_ThrowForbidden_When_CreateUserByAdminHeaderIsInvalid() {
        // Arrange
        AdminCreateUserRequest request = new AdminCreateUserRequest(USER_EMAIL, PASSWORD, UserRole.CLIENT, true);

        // Act
        ResponseStatusException exception = assertThrows(
                ResponseStatusException.class,
                () -> authController.createUserByAdmin(INVALID_INTERNAL_HEADER, request)
        );

        // Assert
        assertEquals(HttpStatus.FORBIDDEN, exception.getStatusCode());
    }

    @Test
    void should_ListUsers_When_InternalHeaderIsValid() {
        // Arrange
        AuthUserSummaryResponse user = new AuthUserSummaryResponse(USER_ID, USER_EMAIL, UserRole.CLIENT.name(), true);
        when(authService.listUsers()).thenReturn(List.of(user));

        // Act
        var result = authController.listUsers(INTERNAL_HEADER);

        // Assert
        assertEquals(HttpStatus.OK, result.getStatusCode());
        assertEquals(1, result.getBody().size());
    }

    @Test
    void should_AdminDeactivateUser_When_InternalHeaderIsValid() {
        // Arrange

        // Act
        var result = authController.adminDeactivate(INTERNAL_HEADER, USER_ID);

        // Assert
        assertEquals(HttpStatus.NO_CONTENT, result.getStatusCode());
        verify(authService).deactivateUser(USER_ID);
    }

    @Test
    void should_AdminActivateUser_When_InternalHeaderIsValid() {
        // Arrange

        // Act
        var result = authController.adminActivate(INTERNAL_HEADER, USER_ID);

        // Assert
        assertEquals(HttpStatus.NO_CONTENT, result.getStatusCode());
        verify(authService).activateUser(USER_ID);
    }
}
