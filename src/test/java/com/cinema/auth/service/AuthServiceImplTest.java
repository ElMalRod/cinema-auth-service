package com.cinema.auth.service;

import com.cinema.auth.domain.UserAuth;
import com.cinema.auth.domain.UserRole;
import com.cinema.auth.dto.LoginRequest;
import com.cinema.auth.dto.LoginResponse;
import com.cinema.auth.dto.MeResponse;
import com.cinema.auth.dto.RegisterRequest;
import com.cinema.auth.exception.InvalidCredentialsException;
import com.cinema.auth.exception.InvalidTokenException;
import com.cinema.auth.exception.UserAlreadyExistsException;
import com.cinema.auth.exception.UserNotFoundException;
import com.cinema.auth.repository.UserAuthRepository;
import com.cinema.auth.security.JwtPrincipal;
import com.cinema.auth.security.JwtProvider;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
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

    @InjectMocks
    private AuthServiceImpl authService;

    @Test
    void shouldRegisterUserAndReturnToken() {
        // Arrange
        RegisterRequest request = new RegisterRequest("admin@test.com", "password123", UserRole.SYSTEM_ADMIN);
        UUID userId = UUID.randomUUID();
        when(repository.existsByEmail("admin@test.com")).thenReturn(false);
        when(passwordEncoder.encode("password123")).thenReturn("encoded-password");
        when(repository.save(any(UserAuth.class))).thenReturn(buildUser(userId, "admin@test.com", "encoded-password", UserRole.SYSTEM_ADMIN));
        when(jwtProvider.generateToken(userId, "admin@test.com", UserRole.SYSTEM_ADMIN)).thenReturn("jwt-token");

        // Act
        LoginResponse response = authService.register(request);

        // Assert
        ArgumentCaptor<UserAuth> captor = ArgumentCaptor.forClass(UserAuth.class);
        verify(repository).save(captor.capture());
        assertEquals("encoded-password", captor.getValue().getPasswordHash());
        assertEquals("jwt-token", response.token());
        assertEquals(userId, response.userId());
    }

    @Test
    void shouldThrowWhenRegisteringExistingUser() {
        // Arrange
        RegisterRequest request = new RegisterRequest("admin@test.com", "password123", UserRole.SYSTEM_ADMIN);
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
                .createdAt(now)
                .updatedAt(now)
                .build();
    }
}
