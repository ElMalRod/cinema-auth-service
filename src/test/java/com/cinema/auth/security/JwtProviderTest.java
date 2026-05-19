package com.cinema.auth.security;

import com.cinema.auth.constants.AuthConstants;
import com.cinema.auth.domain.UserRole;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Duration;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class JwtProviderTest {

    @Test
    void shouldGenerateSignedTokenWithExpectedClaims() throws Exception {
        // Arrange
        KeyPair keyPair = generateKeyPair();
        RsaKeyProvider keyProvider = mock(RsaKeyProvider.class);
        when(keyProvider.getPrivateKey()).thenReturn(keyPair.getPrivate());
        JwtProvider jwtProvider = new JwtProvider(keyProvider, 3600);
        UUID userId = UUID.randomUUID();

        // Act
        String token = jwtProvider.generateToken(userId, "admin@test.com", UserRole.SYSTEM_ADMIN);
        SignedJWT jwt = SignedJWT.parse(token);

        // Assert
        assertTrue(jwt.verify(new RSASSAVerifier((java.security.interfaces.RSAPublicKey) keyPair.getPublic())));
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
        when(keyProvider.getPrivateKey()).thenReturn(keyPair.getPrivate());
        JwtProvider jwtProvider = new JwtProvider(keyProvider, 900);

        // Act
        String token = jwtProvider.generateToken(UUID.randomUUID(), "client@test.com", UserRole.CLIENT);
        SignedJWT jwt = SignedJWT.parse(token);
        Date issuedAt = jwt.getJWTClaimsSet().getIssueTime();
        Date expiration = jwt.getJWTClaimsSet().getExpirationTime();

        // Assert
        long seconds = Duration.between(issuedAt.toInstant(), expiration.toInstant()).toSeconds();
        assertEquals(900L, seconds);
    }

    private KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(AuthConstants.RSA_ALGORITHM);
        generator.initialize(AuthConstants.RSA_KEY_SIZE);
        return generator.generateKeyPair();
    }
}
