package com.cinema.auth.security;

import com.cinema.auth.constants.AuthConstants;
import com.cinema.auth.domain.UserRole;
import com.cinema.auth.service.TokenRevocationService;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class JwtProviderTest {

    @Test
    void shouldGenerateSignedTokenWithExpectedClaims() throws Exception {
        // Arrange
        KeyPair keyPair = generateKeyPair();
        RsaKeyProvider keyProvider = mock(RsaKeyProvider.class);
        TokenRevocationService revocationService = mock(TokenRevocationService.class);
        when(keyProvider.getPrivateKey()).thenReturn((RSAPrivateKey) keyPair.getPrivate());
        when(revocationService.isRevoked("token")).thenReturn(false);
        JwtProvider jwtProvider = new JwtProvider(keyProvider, revocationService, 3600);
        UUID userId = UUID.randomUUID();

        // Act
        String token = jwtProvider.generateToken(userId, "admin@test.com", UserRole.SYSTEM_ADMIN);
        SignedJWT jwt = SignedJWT.parse(token);

        // Assert
        assertTrue(jwt.verify(new RSASSAVerifier((RSAPublicKey) keyPair.getPublic())));
        assertEquals(JWSAlgorithm.RS256, jwt.getHeader().getAlgorithm());
        assertEquals(userId.toString(), jwt.getJWTClaimsSet().getSubject());
        assertEquals("admin@test.com", jwt.getJWTClaimsSet().getStringClaim(AuthConstants.JWT_CLAIM_EMAIL));
        assertEquals(List.of("SYSTEM_ADMIN"), jwt.getJWTClaimsSet().getStringListClaim(AuthConstants.JWT_CLAIM_ROLES));
    }

    @Test
    void shouldApplyConfiguredExpirationTime() throws Exception {
        // Arrange
        KeyPair keyPair = generateKeyPair();
        RsaKeyProvider keyProvider = mock(RsaKeyProvider.class);
        TokenRevocationService revocationService = mock(TokenRevocationService.class);
        when(keyProvider.getPrivateKey()).thenReturn((RSAPrivateKey) keyPair.getPrivate());
        JwtProvider jwtProvider = new JwtProvider(keyProvider, revocationService, 900);

        // Act
        String token = jwtProvider.generateToken(UUID.randomUUID(), "client@test.com", UserRole.CLIENT);
        SignedJWT jwt = SignedJWT.parse(token);
        Date issuedAt = jwt.getJWTClaimsSet().getIssueTime();
        Date expiration = jwt.getJWTClaimsSet().getExpirationTime();

        // Assert
        long seconds = Duration.between(issuedAt.toInstant(), expiration.toInstant()).toSeconds();
        assertEquals(900L, seconds);
    }

    @Test
    void shouldParseValidToken() {
        // Arrange
        KeyPair keyPair = generateUncheckedKeyPair();
        RsaKeyProvider keyProvider = mock(RsaKeyProvider.class);
        TokenRevocationService revocationService = mock(TokenRevocationService.class);
        when(keyProvider.getPrivateKey()).thenReturn((RSAPrivateKey) keyPair.getPrivate());
        when(keyProvider.getPublicKey()).thenReturn((RSAPublicKey) keyPair.getPublic());
        when(revocationService.isRevoked(org.mockito.ArgumentMatchers.anyString())).thenReturn(false);
        JwtProvider jwtProvider = new JwtProvider(keyProvider, revocationService, 3600);
        UUID userId = UUID.randomUUID();

        // Act
        String token = jwtProvider.generateToken(userId, "client@test.com", UserRole.CLIENT);
        Optional<JwtPrincipal> principal = jwtProvider.parseToken(token);

        // Assert
        assertTrue(principal.isPresent());
        assertEquals(userId, principal.get().userId());
        assertEquals(UserRole.CLIENT, principal.get().role());
    }

    @Test
    void shouldReturnEmptyWhenTokenIsExpired() {
        // Arrange
        KeyPair keyPair = generateUncheckedKeyPair();
        RsaKeyProvider keyProvider = mock(RsaKeyProvider.class);
        TokenRevocationService revocationService = mock(TokenRevocationService.class);
        when(keyProvider.getPrivateKey()).thenReturn((RSAPrivateKey) keyPair.getPrivate());
        when(keyProvider.getPublicKey()).thenReturn((RSAPublicKey) keyPair.getPublic());
        when(revocationService.isRevoked(org.mockito.ArgumentMatchers.anyString())).thenReturn(false);
        JwtProvider jwtProvider = new JwtProvider(keyProvider, revocationService, -1);

        // Act
        String token = jwtProvider.generateToken(UUID.randomUUID(), "expired@test.com", UserRole.CLIENT);
        Optional<JwtPrincipal> principal = jwtProvider.parseToken(token);

        // Assert
        assertTrue(principal.isEmpty());
    }

    @Test
    void shouldReturnEmptyWhenTokenSignatureIsInvalid() {
        // Arrange
        KeyPair signingPair = generateUncheckedKeyPair();
        KeyPair verificationPair = generateUncheckedKeyPair();

        TokenRevocationService revocationService = mock(TokenRevocationService.class);
        when(revocationService.isRevoked(org.mockito.ArgumentMatchers.anyString())).thenReturn(false);

        RsaKeyProvider signProvider = mock(RsaKeyProvider.class);
        when(signProvider.getPrivateKey()).thenReturn((RSAPrivateKey) signingPair.getPrivate());
        JwtProvider signingJwtProvider = new JwtProvider(signProvider, revocationService, 3600);

        RsaKeyProvider verifyProvider = mock(RsaKeyProvider.class);
        when(verifyProvider.getPublicKey()).thenReturn((RSAPublicKey) verificationPair.getPublic());
        JwtProvider verifyJwtProvider = new JwtProvider(verifyProvider, revocationService, 3600);

        // Act
        String token = signingJwtProvider.generateToken(UUID.randomUUID(), "bad-sign@test.com", UserRole.CLIENT);
        Optional<JwtPrincipal> principal = verifyJwtProvider.parseToken(token);

        // Assert
        assertFalse(principal.isPresent());
    }

    @Test
    void shouldReturnEmptyWhenTokenIsMalformed() {
        // Arrange
        KeyPair keyPair = generateUncheckedKeyPair();
        RsaKeyProvider keyProvider = mock(RsaKeyProvider.class);
        TokenRevocationService revocationService = mock(TokenRevocationService.class);
        when(keyProvider.getPublicKey()).thenReturn((RSAPublicKey) keyPair.getPublic());
        when(revocationService.isRevoked(org.mockito.ArgumentMatchers.anyString())).thenReturn(false);
        JwtProvider jwtProvider = new JwtProvider(keyProvider, revocationService, 3600);

        // Act
        Optional<JwtPrincipal> principal = jwtProvider.parseToken("malformed-token");

        // Assert
        assertTrue(principal.isEmpty());
    }

    @Test
    void shouldReturnEmptyWhenTokenIsRevoked() {
        // Arrange
        KeyPair keyPair = generateUncheckedKeyPair();
        RsaKeyProvider keyProvider = mock(RsaKeyProvider.class);
        TokenRevocationService revocationService = mock(TokenRevocationService.class);
        when(keyProvider.getPrivateKey()).thenReturn((RSAPrivateKey) keyPair.getPrivate());
        when(keyProvider.getPublicKey()).thenReturn((RSAPublicKey) keyPair.getPublic());
        JwtProvider jwtProvider = new JwtProvider(keyProvider, revocationService, 3600);
        String token = jwtProvider.generateToken(UUID.randomUUID(), "revoked@test.com", UserRole.CLIENT);
        when(revocationService.isRevoked(token)).thenReturn(true);

        // Act
        Optional<JwtPrincipal> principal = jwtProvider.parseToken(token);

        // Assert
        assertTrue(principal.isEmpty());
    }

    private KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(AuthConstants.RSA_ALGORITHM);
        generator.initialize(AuthConstants.RSA_KEY_SIZE);
        return generator.generateKeyPair();
    }

    private KeyPair generateUncheckedKeyPair() {
        try {
            return generateKeyPair();
        } catch (Exception exception) {
            throw new IllegalStateException(exception);
        }
    }
}
