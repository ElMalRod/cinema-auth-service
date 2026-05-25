package com.cinema.auth.service;

import com.cinema.auth.domain.RevokedToken;
import com.cinema.auth.repository.RevokedTokenRepository;
import com.cinema.auth.security.TokenHashService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class TokenRevocationServiceTest {

    private static final String RAW_TOKEN = "raw-token";
    private static final String TOKEN_HASH = "token-hash";
    private static final Instant EXPIRATION = Instant.parse("2026-05-25T02:30:00Z");

    @Mock
    private RevokedTokenRepository repository;

    @Mock
    private TokenHashService tokenHashService;

    private TokenRevocationService tokenRevocationService;

    @BeforeEach
    void setUp() {
        tokenRevocationService = new TokenRevocationService(repository, tokenHashService);
    }

    @Test
    void should_SaveRevokedToken_When_TokenIsNotAlreadyRevoked() {
        // Arrange
        when(tokenHashService.hash(RAW_TOKEN)).thenReturn(TOKEN_HASH);
        when(repository.existsByTokenHash(TOKEN_HASH)).thenReturn(false);

        // Act
        tokenRevocationService.revoke(RAW_TOKEN, EXPIRATION);

        // Assert
        ArgumentCaptor<RevokedToken> tokenCaptor = ArgumentCaptor.forClass(RevokedToken.class);
        verify(repository).deleteByExpiresAtBefore(any(LocalDateTime.class));
        verify(repository).save(tokenCaptor.capture());

        assertEquals(TOKEN_HASH, tokenCaptor.getValue().getTokenHash());
        assertEquals(LocalDateTime.ofInstant(EXPIRATION, ZoneOffset.UTC), tokenCaptor.getValue().getExpiresAt());
    }

    @Test
    void should_NotSaveRevokedToken_When_TokenIsAlreadyRevoked() {
        // Arrange
        when(tokenHashService.hash(RAW_TOKEN)).thenReturn(TOKEN_HASH);
        when(repository.existsByTokenHash(TOKEN_HASH)).thenReturn(true);

        // Act
        tokenRevocationService.revoke(RAW_TOKEN, EXPIRATION);

        // Assert
        verify(repository).deleteByExpiresAtBefore(any(LocalDateTime.class));
        verify(repository, never()).save(any(RevokedToken.class));
    }

    @Test
    void should_ReturnTrue_When_TokenHashExistsInRevokedRepository() {
        // Arrange
        when(tokenHashService.hash(RAW_TOKEN)).thenReturn(TOKEN_HASH);
        when(repository.existsByTokenHash(TOKEN_HASH)).thenReturn(true);

        // Act
        boolean revoked = tokenRevocationService.isRevoked(RAW_TOKEN);

        // Assert
        assertEquals(true, revoked);
        verify(repository).deleteByExpiresAtBefore(any(LocalDateTime.class));
    }

    @Test
    void should_ReturnFalse_When_TokenHashDoesNotExistInRevokedRepository() {
        // Arrange
        when(tokenHashService.hash(RAW_TOKEN)).thenReturn(TOKEN_HASH);
        when(repository.existsByTokenHash(TOKEN_HASH)).thenReturn(false);

        // Act
        boolean revoked = tokenRevocationService.isRevoked(RAW_TOKEN);

        // Assert
        assertEquals(false, revoked);
        verify(tokenHashService).hash(anyString());
    }
}
