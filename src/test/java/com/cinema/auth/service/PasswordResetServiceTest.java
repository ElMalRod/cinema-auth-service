package com.cinema.auth.service;

import com.cinema.auth.domain.PasswordResetToken;
import com.cinema.auth.domain.UserAuth;
import com.cinema.auth.domain.UserRole;
import com.cinema.auth.exception.ResetTokenException;
import com.cinema.auth.repository.PasswordResetTokenRepository;
import com.cinema.auth.repository.UserAuthRepository;
import com.cinema.auth.security.TokenHashService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class PasswordResetServiceTest {

    private static final String USER_EMAIL = "client@test.com";
    private static final String RAW_TOKEN = "raw-token";
    private static final String TOKEN_HASH = "token-hash";
    private static final String NEW_PASSWORD = "new-password123";
    private static final String ENCODED_PASSWORD = "encoded-password";
    private static final String FRONTEND_BASE_URL = "https://frontend.cinema.com/app";
    private static final String FRONTEND_RECOVERY_PATH = "/forgot-password";
    private static final String FRONTEND_RECOVERY_PATH_WITHOUT_LEADING_SLASH = "forgot-password";
    private static final String INVALID_FRONTEND_BASE_URL = "frontend.local///";
    private static final int TOKEN_EXPIRATION_MINUTES = 30;
    private static final int FAILED_LOGIN_ATTEMPTS = 4;
    private static final UUID USER_ID = UUID.fromString("00000000-0000-0000-0000-000000000501");

    @Mock
    private PasswordResetTokenRepository tokenRepository;

    @Mock
    private UserAuthRepository userRepository;

    @Mock
    private TokenHashService tokenHashService;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private PasswordRecoveryNotificationService notificationService;

    private PasswordResetService passwordResetService;

    @BeforeEach
    void setUp() {
        passwordResetService = new PasswordResetService(
                tokenRepository,
                userRepository,
                tokenHashService,
                passwordEncoder,
                notificationService,
                FRONTEND_BASE_URL,
                FRONTEND_RECOVERY_PATH,
                TOKEN_EXPIRATION_MINUTES
        );
    }

    @Test
    void should_DoNothing_When_RequestUserDoesNotExist() {
        // Arrange
        when(userRepository.findByEmail(USER_EMAIL)).thenReturn(Optional.empty());

        // Act
        passwordResetService.request(USER_EMAIL);

        // Assert
        verify(tokenRepository, never()).save(any(PasswordResetToken.class));
        verify(notificationService, never()).sendPasswordRecoveryEmail(anyString(), anyString());
    }

    @Test
    void should_DoNothing_When_RequestUserIsInactive() {
        // Arrange
        UserAuth user = buildUser(false);
        when(userRepository.findByEmail(USER_EMAIL)).thenReturn(Optional.of(user));

        // Act
        passwordResetService.request(USER_EMAIL);

        // Assert
        verify(tokenRepository, never()).save(any(PasswordResetToken.class));
        verify(notificationService, never()).sendPasswordRecoveryEmail(anyString(), anyString());
    }

    @Test
    void should_CreateTokenInvalidateOldOnesAndSendEmail_When_RequestUserIsActive() {
        // Arrange
        UserAuth user = buildUser(true);
        PasswordResetToken oldToken = buildToken(user, LocalDateTime.now().plusMinutes(TOKEN_EXPIRATION_MINUTES));

        when(userRepository.findByEmail(USER_EMAIL)).thenReturn(Optional.of(user));
        when(tokenRepository.findByUser_IdAndUsedAtIsNull(USER_ID)).thenReturn(List.of(oldToken));
        when(tokenHashService.hash(anyString())).thenReturn(TOKEN_HASH);

        // Act
        passwordResetService.request(USER_EMAIL);

        // Assert
        ArgumentCaptor<PasswordResetToken> newTokenCaptor = ArgumentCaptor.forClass(PasswordResetToken.class);
        ArgumentCaptor<String> urlCaptor = ArgumentCaptor.forClass(String.class);

        verify(tokenRepository).saveAll(anyList());
        verify(tokenRepository).save(newTokenCaptor.capture());
        verify(notificationService).sendPasswordRecoveryEmail(org.mockito.ArgumentMatchers.eq(USER_EMAIL), urlCaptor.capture());

        assertNotNull(oldToken.getUsedAt());
        assertEquals(TOKEN_HASH, newTokenCaptor.getValue().getTokenHash());
        assertTrue(urlCaptor.getValue().startsWith("https://frontend.cinema.com/forgot-password?token="));
    }

    @Test
    void should_UseRecoveryPathWithLeadingSlash_When_PathHasNoLeadingSlash() {
        // Arrange
        PasswordResetService serviceWithPathWithoutLeadingSlash = new PasswordResetService(
                tokenRepository,
                userRepository,
                tokenHashService,
                passwordEncoder,
                notificationService,
                FRONTEND_BASE_URL,
                FRONTEND_RECOVERY_PATH_WITHOUT_LEADING_SLASH,
                TOKEN_EXPIRATION_MINUTES
        );
        UserAuth user = buildUser(true);
        when(userRepository.findByEmail(USER_EMAIL)).thenReturn(Optional.of(user));
        when(tokenRepository.findByUser_IdAndUsedAtIsNull(USER_ID)).thenReturn(List.of());
        when(tokenHashService.hash(anyString())).thenReturn(TOKEN_HASH);

        // Act
        serviceWithPathWithoutLeadingSlash.request(USER_EMAIL);

        // Assert
        ArgumentCaptor<String> urlCaptor = ArgumentCaptor.forClass(String.class);
        verify(notificationService).sendPasswordRecoveryEmail(org.mockito.ArgumentMatchers.eq(USER_EMAIL), urlCaptor.capture());
        assertTrue(urlCaptor.getValue().startsWith("https://frontend.cinema.com/forgot-password?token="));
    }

    @Test
    void should_RemoveTrailingSlashes_When_ConfiguredFrontendUrlIsNotAValidUri() {
        // Arrange
        PasswordResetService serviceWithInvalidUrl = new PasswordResetService(
                tokenRepository,
                userRepository,
                tokenHashService,
                passwordEncoder,
                notificationService,
                INVALID_FRONTEND_BASE_URL,
                FRONTEND_RECOVERY_PATH,
                TOKEN_EXPIRATION_MINUTES
        );
        UserAuth user = buildUser(true);
        when(userRepository.findByEmail(USER_EMAIL)).thenReturn(Optional.of(user));
        when(tokenRepository.findByUser_IdAndUsedAtIsNull(USER_ID)).thenReturn(List.of());
        when(tokenHashService.hash(anyString())).thenReturn(TOKEN_HASH);

        // Act
        serviceWithInvalidUrl.request(USER_EMAIL);

        // Assert
        ArgumentCaptor<String> urlCaptor = ArgumentCaptor.forClass(String.class);
        verify(notificationService).sendPasswordRecoveryEmail(org.mockito.ArgumentMatchers.eq(USER_EMAIL), urlCaptor.capture());
        assertTrue(urlCaptor.getValue().startsWith("frontend.local/forgot-password?token="));
    }

    @Test
    void should_ResetPasswordAndMarkTokenAsUsed_When_TokenIsValid() {
        // Arrange
        UserAuth user = buildUser(true);
        user.setFailedLoginAttempts(FAILED_LOGIN_ATTEMPTS);
        user.setLockedUntil(LocalDateTime.now().plusMinutes(1));

        PasswordResetToken token = buildToken(user, LocalDateTime.now().plusMinutes(TOKEN_EXPIRATION_MINUTES));
        token.setUsedAt(null);

        when(tokenHashService.hash(RAW_TOKEN)).thenReturn(TOKEN_HASH);
        when(tokenRepository.findByTokenHash(TOKEN_HASH)).thenReturn(Optional.of(token));
        when(passwordEncoder.encode(NEW_PASSWORD)).thenReturn(ENCODED_PASSWORD);

        // Act
        passwordResetService.reset(RAW_TOKEN, NEW_PASSWORD);

        // Assert
        assertEquals(ENCODED_PASSWORD, user.getPasswordHash());
        assertEquals(0, user.getFailedLoginAttempts());
        assertNull(user.getLockedUntil());
        assertNotNull(user.getUpdatedAt());
        assertNotNull(token.getUsedAt());
        verify(userRepository).save(user);
        verify(tokenRepository).save(token);
    }

    @Test
    void should_ThrowResetTokenException_When_TokenDoesNotExist() {
        // Arrange
        when(tokenHashService.hash(RAW_TOKEN)).thenReturn(TOKEN_HASH);
        when(tokenRepository.findByTokenHash(TOKEN_HASH)).thenReturn(Optional.empty());

        // Act
        ResetTokenException exception = assertThrows(ResetTokenException.class, () -> passwordResetService.reset(RAW_TOKEN, NEW_PASSWORD));

        // Assert
        assertEquals("Token de recuperacion invalido o expirado", exception.getMessage());
        verify(userRepository, never()).save(any(UserAuth.class));
    }

    @Test
    void should_ThrowResetTokenException_When_TokenWasAlreadyUsed() {
        // Arrange
        UserAuth user = buildUser(true);
        PasswordResetToken token = buildToken(user, LocalDateTime.now().plusMinutes(TOKEN_EXPIRATION_MINUTES));
        token.setUsedAt(LocalDateTime.now());

        when(tokenHashService.hash(RAW_TOKEN)).thenReturn(TOKEN_HASH);
        when(tokenRepository.findByTokenHash(TOKEN_HASH)).thenReturn(Optional.of(token));

        // Act
        ResetTokenException exception = assertThrows(ResetTokenException.class, () -> passwordResetService.reset(RAW_TOKEN, NEW_PASSWORD));

        // Assert
        assertEquals("Token de recuperacion invalido o expirado", exception.getMessage());
        verify(userRepository, never()).save(any(UserAuth.class));
    }

    @Test
    void should_ThrowResetTokenException_When_TokenIsExpired() {
        // Arrange
        UserAuth user = buildUser(true);
        PasswordResetToken token = buildToken(user, LocalDateTime.now().minusMinutes(1));

        when(tokenHashService.hash(RAW_TOKEN)).thenReturn(TOKEN_HASH);
        when(tokenRepository.findByTokenHash(TOKEN_HASH)).thenReturn(Optional.of(token));

        // Act
        ResetTokenException exception = assertThrows(ResetTokenException.class, () -> passwordResetService.reset(RAW_TOKEN, NEW_PASSWORD));

        // Assert
        assertEquals("Token de recuperacion invalido o expirado", exception.getMessage());
        verify(userRepository, never()).save(any(UserAuth.class));
    }

    private UserAuth buildUser(boolean active) {
        return UserAuth.builder()
                .id(USER_ID)
                .email(USER_EMAIL)
                .passwordHash("old-password")
                .role(UserRole.CLIENT)
                .active(active)
                .requiresPasswordChange(false)
                .failedLoginAttempts(0)
                .createdAt(LocalDateTime.now())
                .updatedAt(LocalDateTime.now())
                .build();
    }

    private PasswordResetToken buildToken(UserAuth user, LocalDateTime expiresAt) {
        return PasswordResetToken.builder()
                .id(UUID.randomUUID())
                .user(user)
                .tokenHash(TOKEN_HASH)
                .expiresAt(expiresAt)
                .createdAt(LocalDateTime.now())
                .build();
    }
}
