package com.cinema.auth.service;

import com.cinema.auth.domain.UserAuth;
import com.cinema.auth.domain.UserRole;
import com.cinema.auth.dto.AdminCreateUserRequest;
import com.cinema.auth.dto.AdminCreateUserResponse;
import com.cinema.auth.dto.ChangePasswordRequest;
import com.cinema.auth.dto.ForgotPasswordRequest;
import com.cinema.auth.dto.LoginRequest;
import com.cinema.auth.dto.LoginResponse;
import com.cinema.auth.dto.MeResponse;
import com.cinema.auth.dto.RegisterRequest;
import com.cinema.auth.dto.ResetPasswordRequest;
import com.cinema.auth.exception.AccountLockedException;
import com.cinema.auth.exception.InvalidCredentialsException;
import com.cinema.auth.exception.InvalidRegistrationException;
import com.cinema.auth.exception.InvalidTokenException;
import com.cinema.auth.exception.UserAlreadyExistsException;
import com.cinema.auth.exception.UserNotFoundException;
import com.cinema.auth.repository.UserAuthRepository;
import com.cinema.auth.security.JwtPrincipal;
import com.cinema.auth.security.JwtProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthServiceImplTest {

    @Mock
    private UserAuthRepository repository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private JwtProvider jwtProvider;

    @Mock
    private PasswordResetService passwordResetService;

    @Mock
    private TokenRevocationService tokenRevocationService;

    @Mock
    private UserEventPublisher userEventPublisher;

    private AuthServiceImpl authService;

    @BeforeEach
    void setUp() {
        authService = new AuthServiceImpl(
                repository,
                passwordEncoder,
                jwtProvider,
                passwordResetService,
                tokenRevocationService,
                userEventPublisher,
                5,
                15
        );
    }

    @Test
    void shouldRegisterClientAndPublishUserCreated() {
        // Arrange
        RegisterRequest request = new RegisterRequest("Cliente Uno", "5551234", "cliente@test.com", "password123", UserRole.CLIENT);
        UUID userId = UUID.randomUUID();
        when(repository.existsByEmail("cliente@test.com")).thenReturn(false);
        when(passwordEncoder.encode("password123")).thenReturn("encoded-password");
        when(repository.save(any(UserAuth.class))).thenReturn(buildUser(userId, "cliente@test.com", "encoded-password", UserRole.CLIENT));
        when(jwtProvider.generateToken(userId, "cliente@test.com", UserRole.CLIENT)).thenReturn("jwt-token");

        // Act
        LoginResponse response = authService.register(request);

        // Assert
        ArgumentCaptor<UserAuth> captor = ArgumentCaptor.forClass(UserAuth.class);
        verify(repository).save(captor.capture());
        assertEquals("encoded-password", captor.getValue().getPasswordHash());
        assertEquals("jwt-token", response.token());
        verify(userEventPublisher).publishUserCreated(userId, "Cliente Uno", "5551234");
    }

    @Test
    void shouldRegisterCinemaAdminWithCompanyNameAndPublishCinemaAdminCreated() {
        // Arrange
        RegisterRequest request = new RegisterRequest(
                "Admin Cine",
                "5552222",
                "Cinema Central",
                "cineadmin@test.com",
                "password123",
                UserRole.CINEMA_ADMIN
        );
        UUID userId = UUID.randomUUID();
        when(repository.existsByEmail("cineadmin@test.com")).thenReturn(false);
        when(passwordEncoder.encode("password123")).thenReturn("encoded-password");
        when(repository.save(any(UserAuth.class))).thenReturn(buildUser(userId, "cineadmin@test.com", "encoded-password", UserRole.CINEMA_ADMIN));
        when(jwtProvider.generateToken(userId, "cineadmin@test.com", UserRole.CINEMA_ADMIN)).thenReturn("jwt-token");

        // Act
        LoginResponse response = authService.register(request);

        // Assert
        assertEquals("jwt-token", response.token());
        verify(userEventPublisher).publishCinemaAdminCreated(userId, "Admin Cine", "5552222", "Cinema Central");
    }

    @Test
    void shouldThrowWhenRegisteringCinemaAdminWithoutCompanyName() {
        // Arrange
        RegisterRequest request = new RegisterRequest(
                "Admin Cine",
                "5552222",
                "   ",
                "cineadmin@test.com",
                "password123",
                UserRole.CINEMA_ADMIN
        );
        when(repository.existsByEmail("cineadmin@test.com")).thenReturn(false);

        // Act
        RuntimeException exception = assertThrows(InvalidRegistrationException.class, () -> authService.register(request));

        // Assert
        assertEquals("El nombre de la empresa/cine es obligatorio para CINEMA_ADMIN", exception.getMessage());
        verify(repository, never()).save(any(UserAuth.class));
        verify(userEventPublisher, never()).publishCinemaAdminCreated(any(), any(), any(), any());
    }

    @Test
    void shouldRegisterAdvertiserAndPublishAdvertiserCreated() {
        // Arrange
        RegisterRequest request = new RegisterRequest("Anunciante Uno", "5553333", "ads@test.com", "password123", UserRole.ADVERTISER);
        UUID userId = UUID.randomUUID();
        when(repository.existsByEmail("ads@test.com")).thenReturn(false);
        when(passwordEncoder.encode("password123")).thenReturn("encoded-password");
        when(repository.save(any(UserAuth.class))).thenReturn(buildUser(userId, "ads@test.com", "encoded-password", UserRole.ADVERTISER));
        when(jwtProvider.generateToken(userId, "ads@test.com", UserRole.ADVERTISER)).thenReturn("jwt-token");

        // Act
        LoginResponse response = authService.register(request);

        // Assert
        assertEquals("jwt-token", response.token());
        verify(userEventPublisher).publishAdvertiserCreated(userId, "Anunciante Uno", "5553333");
    }

    @Test
    void shouldThrowWhenRegisteringExistingUser() {
        // Arrange
        RegisterRequest request = new RegisterRequest("Admin Test", "5551234", "admin@test.com", "password123", UserRole.SYSTEM_ADMIN);
        when(repository.existsByEmail("admin@test.com")).thenReturn(true);

        // Act
        RuntimeException exception = assertThrows(UserAlreadyExistsException.class, () -> authService.register(request));

        // Assert
        assertEquals("El usuario ya existe", exception.getMessage());
    }

    @Test
    void shouldLoginWithValidCredentials() {
        // Arrange
        UUID userId = UUID.randomUUID();
        UserAuth user = buildUser(userId, "client@test.com", "encoded", UserRole.CLIENT);
        when(repository.findByEmail("client@test.com")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("password123", "encoded")).thenReturn(true);
        when(jwtProvider.generateToken(userId, "client@test.com", UserRole.CLIENT)).thenReturn("login-token");

        // Act
        LoginResponse response = authService.login(new LoginRequest("client@test.com", "password123"));

        // Assert
        assertEquals("login-token", response.token());
        assertEquals("CLIENT", response.role());
        assertEquals(0, user.getFailedLoginAttempts());
        assertEquals(null, user.getLockedUntil());
    }

    @Test
    void shouldRejectLoginWithInvalidCredentials() {
        // Arrange
        UUID userId = UUID.randomUUID();
        UserAuth user = buildUser(userId, "client@test.com", "encoded", UserRole.CLIENT);
        when(repository.findByEmail("client@test.com")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("wrong", "encoded")).thenReturn(false);

        // Act
        RuntimeException exception = assertThrows(InvalidCredentialsException.class,
                () -> authService.login(new LoginRequest("client@test.com", "wrong")));

        // Assert
        assertEquals("Credenciales invalidas", exception.getMessage());
        assertEquals(1, user.getFailedLoginAttempts());
    }

    @Test
    void shouldLockAccountAfterFiveFailedAttempts() {
        // Arrange
        UserAuth user = buildUser(UUID.randomUUID(), "client@test.com", "encoded", UserRole.CLIENT);
        user.setFailedLoginAttempts(4);
        when(repository.findByEmail("client@test.com")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("wrong", "encoded")).thenReturn(false);

        // Act
        assertThrows(InvalidCredentialsException.class,
                () -> authService.login(new LoginRequest("client@test.com", "wrong")));

        // Assert
        assertEquals(5, user.getFailedLoginAttempts());
        assertTrue(user.getLockedUntil().isAfter(LocalDateTime.now().plusMinutes(14)));
    }

    @Test
    void shouldRejectLockedUserLogin() {
        // Arrange
        UserAuth user = buildUser(UUID.randomUUID(), "client@test.com", "encoded", UserRole.CLIENT);
        user.setLockedUntil(LocalDateTime.now().plusMinutes(10));
        when(repository.findByEmail("client@test.com")).thenReturn(Optional.of(user));

        // Act
        RuntimeException exception = assertThrows(AccountLockedException.class,
                () -> authService.login(new LoginRequest("client@test.com", "password123")));

        // Assert
        assertEquals("Cuenta bloqueada temporalmente por intentos fallidos", exception.getMessage());
        verify(passwordEncoder, never()).matches(any(), any());
    }

    @Test
    void shouldReturnCurrentUserFromToken() {
        // Arrange
        UUID userId = UUID.randomUUID();
        UserAuth user = buildUser(userId, "admin@test.com", "encoded", UserRole.SYSTEM_ADMIN);
        JwtPrincipal principal = new JwtPrincipal(userId, "admin@test.com", UserRole.SYSTEM_ADMIN);
        when(jwtProvider.parseToken("token-value")).thenReturn(Optional.of(principal));
        when(repository.findById(userId)).thenReturn(Optional.of(user));

        // Act
        MeResponse response = authService.getCurrentUser("Bearer token-value");

        // Assert
        assertEquals(userId, response.userId());
        assertEquals("admin@test.com", response.email());
        assertTrue(response.active());
    }

    @Test
    void shouldRejectRequestWhenAuthorizationHeaderIsInvalid() {
        // Arrange

        // Act
        RuntimeException exception = assertThrows(InvalidTokenException.class,
                () -> authService.getCurrentUser("token-value"));

        // Assert
        assertEquals("Token invalido", exception.getMessage());
    }

    @Test
    void shouldThrowWhenCurrentUserDoesNotExist() {
        // Arrange
        UUID userId = UUID.randomUUID();
        JwtPrincipal principal = new JwtPrincipal(userId, "ghost@test.com", UserRole.CLIENT);
        when(jwtProvider.parseToken("token-value")).thenReturn(Optional.of(principal));
        when(repository.findById(userId)).thenReturn(Optional.empty());

        // Act
        RuntimeException exception = assertThrows(UserNotFoundException.class,
                () -> authService.getCurrentUser("Bearer token-value"));

        // Assert
        assertEquals("Usuario no encontrado", exception.getMessage());
    }

    @Test
    void shouldLogoutAndRevokeToken() {
        // Arrange
        when(jwtProvider.parseToken("logout-token")).thenReturn(Optional.of(
                new JwtPrincipal(UUID.randomUUID(), "client@test.com", UserRole.CLIENT)
        ));
        when(jwtProvider.extractExpiration("logout-token")).thenReturn(Optional.of(Instant.now().plusSeconds(100)));

        // Act
        authService.logout("Bearer logout-token");

        // Assert
        verify(tokenRevocationService).revoke(any(), any());
    }

    @Test
    void shouldRequestPasswordRecovery() {
        // Arrange
        ForgotPasswordRequest request = new ForgotPasswordRequest("Client@Test.com");

        // Act
        authService.requestPasswordRecovery(request);

        // Assert
        verify(passwordResetService).request("client@test.com");
    }

    @Test
    void shouldResetPassword() {
        // Arrange
        ResetPasswordRequest request = new ResetPasswordRequest("plain-token", "newPassword123");

        // Act
        authService.resetPassword(request);

        // Assert
        verify(passwordResetService).reset("plain-token", "newPassword123");
    }

    @Test
    void shouldChangePasswordWhenCurrentPasswordMatches() {
        // Arrange
        UUID userId = UUID.randomUUID();
        UserAuth user = buildUser(userId, "client@test.com", "encoded", UserRole.CLIENT);
        JwtPrincipal principal = new JwtPrincipal(userId, "client@test.com", UserRole.CLIENT);
        ChangePasswordRequest request = new ChangePasswordRequest("password123", "newPassword123");
        when(jwtProvider.parseToken("change-token")).thenReturn(Optional.of(principal));
        when(repository.findById(userId)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("password123", "encoded")).thenReturn(true);
        when(passwordEncoder.encode("newPassword123")).thenReturn("encoded-new-password");

        // Act
        authService.changePassword("Bearer change-token", request);

        // Assert
        assertEquals("encoded-new-password", user.getPasswordHash());
        verify(repository).save(user);
    }

    @Test
    void shouldRejectPasswordChangeWhenCurrentPasswordDoesNotMatch() {
        // Arrange
        UUID userId = UUID.randomUUID();
        UserAuth user = buildUser(userId, "client@test.com", "encoded", UserRole.CLIENT);
        JwtPrincipal principal = new JwtPrincipal(userId, "client@test.com", UserRole.CLIENT);
        ChangePasswordRequest request = new ChangePasswordRequest("wrong-password", "newPassword123");
        when(jwtProvider.parseToken("change-token")).thenReturn(Optional.of(principal));
        when(repository.findById(userId)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("wrong-password", "encoded")).thenReturn(false);

        // Act
        RuntimeException exception = assertThrows(InvalidCredentialsException.class,
                () -> authService.changePassword("Bearer change-token", request));

        // Assert
        assertEquals("Credenciales invalidas", exception.getMessage());
        verify(repository, never()).save(user);
    }

    @Test
    void shouldDeactivateUser() {
        // Arrange
        UUID userId = UUID.randomUUID();
        UserAuth user = buildUser(userId, "client@test.com", "encoded", UserRole.CLIENT);
        when(repository.findById(userId)).thenReturn(Optional.of(user));

        // Act
        authService.deactivateUser(userId);

        // Assert
        assertFalse(user.isActive());
        verify(repository).save(user);
    }

    @Test
    void shouldThrowWhenDeactivatingMissingUser() {
        // Arrange
        UUID userId = UUID.randomUUID();
        when(repository.findById(userId)).thenReturn(Optional.empty());

        // Act
        RuntimeException exception = assertThrows(UserNotFoundException.class,
                () -> authService.deactivateUser(userId));

        // Assert
        assertEquals("Usuario no encontrado", exception.getMessage());
    }


    @Test
    void shouldCreateUserByAdminAndPublishUserCreatedForClient() {
        // Arrange
        UUID userId = UUID.randomUUID();
        AdminCreateUserRequest request = new AdminCreateUserRequest(
                "Cliente Admin",
                "50112233",
                null,
                "client-admin@test.com",
                "password123",
                UserRole.CLIENT,
                true
        );
        when(repository.existsByEmail("client-admin@test.com")).thenReturn(false);
        when(passwordEncoder.encode("password123")).thenReturn("encoded-password");
        when(repository.save(any(UserAuth.class))).thenReturn(buildUser(userId, "client-admin@test.com", "encoded-password", UserRole.CLIENT));

        // Act
        AdminCreateUserResponse response = authService.createUserByAdmin(request);

        // Assert
        assertEquals(userId, response.id());
        verify(userEventPublisher).publishUserCreated(userId, "Cliente Admin", "50112233");
    }

    @Test
    void shouldCreateUserByAdminAndPublishCinemaAdminCreatedWithOptionalCompanyName() {
        // Arrange
        UUID userId = UUID.randomUUID();
        AdminCreateUserRequest request = new AdminCreateUserRequest(
                "Admin Cine",
                "55443322",
                "  ",
                "cinema-admin@test.com",
                "password123",
                UserRole.CINEMA_ADMIN,
                true
        );
        when(repository.existsByEmail("cinema-admin@test.com")).thenReturn(false);
        when(passwordEncoder.encode("password123")).thenReturn("encoded-password");
        when(repository.save(any(UserAuth.class))).thenReturn(buildUser(userId, "cinema-admin@test.com", "encoded-password", UserRole.CINEMA_ADMIN));

        // Act
        authService.createUserByAdmin(request);

        // Assert
        verify(userEventPublisher).publishCinemaAdminCreated(userId, "Admin Cine", "55443322", null);
    }

    @Test
    void shouldCreateUserByAdminAndPublishAdvertiserCreated() {
        // Arrange
        UUID userId = UUID.randomUUID();
        AdminCreateUserRequest request = new AdminCreateUserRequest(
                "Anunciante Admin",
                "44556677",
                null,
                "advertiser-admin@test.com",
                "password123",
                UserRole.ADVERTISER,
                true
        );
        when(repository.existsByEmail("advertiser-admin@test.com")).thenReturn(false);
        when(passwordEncoder.encode("password123")).thenReturn("encoded-password");
        when(repository.save(any(UserAuth.class))).thenReturn(buildUser(userId, "advertiser-admin@test.com", "encoded-password", UserRole.ADVERTISER));

        // Act
        authService.createUserByAdmin(request);

        // Assert
        verify(userEventPublisher).publishAdvertiserCreated(userId, "Anunciante Admin", "44556677");
    }
    private UserAuth buildUser(UUID userId, String email, String passwordHash, UserRole role) {
        LocalDateTime now = LocalDateTime.now();
        return UserAuth.builder()
                .id(userId)
                .email(email)
                .passwordHash(passwordHash)
                .role(role)
                .active(true)
                .failedLoginAttempts(0)
                .lockedUntil(null)
                .createdAt(now)
                .updatedAt(now)
                .build();
    }
}




