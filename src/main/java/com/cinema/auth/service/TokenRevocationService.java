package com.cinema.auth.service;

import com.cinema.auth.domain.RevokedToken;
import com.cinema.auth.repository.RevokedTokenRepository;
import com.cinema.auth.security.TokenHashService;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;

@Service
public class TokenRevocationService {

    private final RevokedTokenRepository repository;
    private final TokenHashService tokenHashService;

    public TokenRevocationService(RevokedTokenRepository repository, TokenHashService tokenHashService) {
        this.repository = repository;
        this.tokenHashService = tokenHashService;
    }

    @Transactional
    public void revoke(String rawToken, Instant expiration) {
        cleanupExpired();
        String tokenHash = tokenHashService.hash(rawToken);
        if (repository.existsByTokenHash(tokenHash)) {
            return;
        }
        RevokedToken token = RevokedToken.builder()
                .tokenHash(tokenHash)
                .expiresAt(LocalDateTime.ofInstant(expiration, ZoneOffset.UTC))
                .createdAt(LocalDateTime.now())
                .build();
        repository.save(token);
    }

    @Transactional
    public boolean isRevoked(String rawToken) {
        cleanupExpired();
        return repository.existsByTokenHash(tokenHashService.hash(rawToken));
    }

    private void cleanupExpired() {
        repository.deleteByExpiresAtBefore(LocalDateTime.now());
    }
}
