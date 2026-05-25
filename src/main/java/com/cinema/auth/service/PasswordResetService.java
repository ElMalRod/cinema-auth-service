package com.cinema.auth.service;

import com.cinema.auth.domain.PasswordResetToken;
import com.cinema.auth.domain.UserAuth;
import com.cinema.auth.exception.ResetTokenException;
import com.cinema.auth.repository.PasswordResetTokenRepository;
import com.cinema.auth.repository.UserAuthRepository;
import com.cinema.auth.security.TokenHashService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.net.URI;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
public class PasswordResetService {

    private final PasswordResetTokenRepository tokenRepository;
    private final UserAuthRepository userRepository;
    private final TokenHashService tokenHashService;
    private final PasswordEncoder passwordEncoder;
    private final PasswordRecoveryNotificationService notificationService;
    private final String frontendBaseUrl;
    private final String frontendPasswordRecoveryPath;
    private final int tokenExpirationMinutes;

    public PasswordResetService(
            PasswordResetTokenRepository tokenRepository,
            UserAuthRepository userRepository,
            TokenHashService tokenHashService,
            PasswordEncoder passwordEncoder,
            PasswordRecoveryNotificationService notificationService,
            @Value("${app.frontend-base-url}") String frontendBaseUrl,
            @Value("${app.frontend-password-recovery-path}") String frontendPasswordRecoveryPath,
            @Value("${auth.reset-token.expiration-minutes:30}") int tokenExpirationMinutes
    ) {
        this.tokenRepository = tokenRepository;
        this.userRepository = userRepository;
        this.tokenHashService = tokenHashService;
        this.passwordEncoder = passwordEncoder;
        this.notificationService = notificationService;
        this.frontendBaseUrl = frontendBaseUrl;
        this.frontendPasswordRecoveryPath = frontendPasswordRecoveryPath;
        this.tokenExpirationMinutes = tokenExpirationMinutes;
    }

    @Transactional
    public void request(String email) {
        Optional<UserAuth> user = userRepository.findByEmail(email);
        if (user.isEmpty() || !user.get().isActive()) {
            return;
        }
        String plainToken = createToken(user.get());
        notificationService.sendPasswordRecoveryEmail(user.get().getEmail(), buildRecoveryUrl(plainToken));
    }

    @Transactional
    public void reset(String rawToken, String newPassword) {
        PasswordResetToken resetToken = findValidToken(rawToken);
        UserAuth user = resetToken.getUser();
        user.setPasswordHash(passwordEncoder.encode(newPassword));
        user.setFailedLoginAttempts(0);
        user.setLockedUntil(null);
        user.setUpdatedAt(LocalDateTime.now());
        userRepository.save(user);
        resetToken.setUsedAt(LocalDateTime.now());
        tokenRepository.save(resetToken);
    }

    private PasswordResetToken findValidToken(String rawToken) {
        String tokenHash = tokenHashService.hash(rawToken);
        PasswordResetToken token = tokenRepository.findByTokenHash(tokenHash).orElseThrow(ResetTokenException::new);
        if (token.getUsedAt() != null || token.getExpiresAt().isBefore(LocalDateTime.now())) {
            throw new ResetTokenException();
        }
        return token;
    }

    private String createToken(UserAuth user) {
        invalidateOldTokens(user.getId());
        String plainToken = UUID.randomUUID().toString();
        PasswordResetToken token = PasswordResetToken.builder()
                .user(user)
                .tokenHash(tokenHashService.hash(plainToken))
                .expiresAt(LocalDateTime.now().plusMinutes(tokenExpirationMinutes))
                .createdAt(LocalDateTime.now())
                .build();
        tokenRepository.save(token);
        return plainToken;
    }

    private void invalidateOldTokens(UUID userId) {
        List<PasswordResetToken> activeTokens = tokenRepository.findByUser_IdAndUsedAtIsNull(userId);
        LocalDateTime now = LocalDateTime.now();
        activeTokens.forEach(token -> token.setUsedAt(now));
        tokenRepository.saveAll(activeTokens);
    }

    private String buildRecoveryUrl(String plainToken) {
        return normalizeFrontendBaseUrl() + normalizeFrontendRecoveryPath() + "?token=" + plainToken;
    }

    private String normalizeFrontendBaseUrl() {
        String configured = frontendBaseUrl == null ? "" : frontendBaseUrl.trim();
        try {
            URI uri = URI.create(configured);
            if (uri.getScheme() != null && uri.getHost() != null) {
                String authority = uri.getAuthority();
                return uri.getScheme() + "://" + authority;
            }
        } catch (IllegalArgumentException ignored) {
        }
        return configured.replaceAll("/+$", "");
    }

    private String normalizeFrontendRecoveryPath() {
        String configuredPath = frontendPasswordRecoveryPath == null ? "" : frontendPasswordRecoveryPath.trim();
        if (configuredPath.isEmpty()) {
            return "/forgot-password";
        }
        return configuredPath.startsWith("/") ? configuredPath : "/" + configuredPath;
    }
}
