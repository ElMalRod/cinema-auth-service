package com.cinema.auth.service;

import com.cinema.auth.domain.UserAuth;
import com.cinema.auth.domain.UserRole;
import com.cinema.auth.dto.ChangePasswordRequest;
import com.cinema.auth.dto.ForgotPasswordRequest;
import com.cinema.auth.dto.LoginRequest;
import com.cinema.auth.dto.LoginResponse;
import com.cinema.auth.dto.MeResponse;
import com.cinema.auth.dto.RegisterRequest;
import com.cinema.auth.dto.ResetPasswordRequest;
import com.cinema.auth.exception.AccountLockedException;
import com.cinema.auth.exception.InvalidCredentialsException;
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
import org.springframework.context.ApplicationContext;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.Map;
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
    private ApplicationContext applicationContext;

    private AuthServiceImpl authService;

    @BeforeEach
    void setUp() {
        authService = new AuthServiceImpl(
                repository,
                passwordEncoder,
                jwtProvider,
                passwordResetService,
                tokenRevocationService,
                applicationContext,
                5,
                15
        );
    }

    @Test
    void shouldRegisterUserAndReturnToken() {
        // Arrange
        RegisterRequest request = new RegisterRequest("Admin Test", "5551234", "admin@test.com", "password123", UserRole.SYSTEM_ADMIN);
        UUID userId = UUID.randomUUID();
        FakeKafkaTemplate fakeKafkaTemplate = new FakeKafkaTemplate();
        when(repository.existsByEmail("admin@test.com")).thenReturn(false);
        when(passwordEncoder.encode("password123")).thenReturn("encoded-password");
        when(repository.save(any(UserAuth.class))).thenReturn(buildUser(userId, "admin@test.com", "encoded-password", UserRole.SYSTEM_ADMIN));
        when(jwtProvider.generateToken(userId, "admin@test.com", UserRole.SYSTEM_ADMIN)).thenReturn("jwt-token");
        when(applicationContext.containsBean("kafkaTemplate")).thenReturn(true);
        when(applicationContext.getBean("kafkaTemplate")).thenReturn(fakeKafkaTemplate);

        // Act
        LoginResponse response = authService.register(request);

        // Assert
        ArgumentCaptor<UserAuth> captor = ArgumentCaptor.forClass(UserAuth.class);
        verify(repository).save(captor.capture());
        assertEquals("encoded-password", captor.getValue().getPasswordHash());
        assertEquals("jwt-token", response.token());
        assertEquals(userId, response.userId());
        @SuppressWarnings("unchecked")
        Map<String, Object> payload = (Map<String, Object>) fakeKafkaTemplate.payload;
        assertEquals("user-events", fakeKafkaTemplate.topic);
        assertEquals("USER_CREATED", payload.get("event"));
        assertEquals(userId.toString(), payload.get("id"));
        assertEquals("Admin Test", payload.get("name"));
        assertEquals("5551234", payload.get("phone"));
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

    private static final class FakeKafkaTemplate {
        private String topic;
        private Object payload;

        public void send(String topic, Object payload) {
            this.topic = topic;
            this.payload = payload;
        }
    }
}


