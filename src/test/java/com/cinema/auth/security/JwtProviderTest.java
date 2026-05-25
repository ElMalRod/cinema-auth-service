package com.cinema.auth.security;

import com.cinema.auth.constants.AuthConstants;
import com.cinema.auth.domain.UserRole;
import com.cinema.auth.service.TokenRevocationService;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class JwtProviderTest {

    private static final long DEFAULT_EXPIRATION_SECONDS = 3600L;
    private static final long SHORT_EXPIRATION_SECONDS = 900L;
    private static final long EXPIRED_EXPIRATION_SECONDS = -1L;
    private static final String EMAIL = "client@test.com";
    private static final String MALFORMED_TOKEN = "malformed-token";
    private static final String INVALID_UUID_SUBJECT = "not-an-uuid";
    private static final String INVALID_ROLE = "NOT_A_ROLE";
    private static final String TOKEN_WITHOUT_SUBJECT = "";
    private static final UUID USER_ID = UUID.fromString("00000000-0000-0000-0000-000000000201");

    @Mock
    private RsaKeyProvider rsaKeyProvider;

    @Mock
    private TokenRevocationService tokenRevocationService;

    private KeyPair keyPair;

    @BeforeEach
    void setUp() {
        keyPair = generateKeyPair();
    }

    @Test
    void should_GenerateSignedTokenWithExpectedClaims_When_InputDataIsValid() throws Exception {
        // Arrange
        JwtProvider jwtProvider = buildJwtProviderForGenerate(DEFAULT_EXPIRATION_SECONDS);

        // Act
        String token = jwtProvider.generateToken(USER_ID, EMAIL, UserRole.CLIENT);
        SignedJWT signedJWT = SignedJWT.parse(token);

        // Assert
        assertTrue(signedJWT.verify(new RSASSAVerifier((RSAPublicKey) keyPair.getPublic())));
        assertEquals(JWSAlgorithm.RS256, signedJWT.getHeader().getAlgorithm());
        assertEquals(USER_ID.toString(), signedJWT.getJWTClaimsSet().getSubject());
        assertEquals(EMAIL, signedJWT.getJWTClaimsSet().getStringClaim(AuthConstants.JWT_CLAIM_EMAIL));
        assertEquals(List.of(UserRole.CLIENT.name()), signedJWT.getJWTClaimsSet().getStringListClaim(AuthConstants.JWT_CLAIM_ROLES));
    }

    @Test
    void should_ApplyConfiguredExpiration_When_TokenIsGenerated() throws Exception {
        // Arrange
        JwtProvider jwtProvider = buildJwtProviderForGenerate(SHORT_EXPIRATION_SECONDS);

        // Act
        String token = jwtProvider.generateToken(USER_ID, EMAIL, UserRole.CLIENT);
        SignedJWT signedJWT = SignedJWT.parse(token);
        Date issuedAt = signedJWT.getJWTClaimsSet().getIssueTime();
        Date expiration = signedJWT.getJWTClaimsSet().getExpirationTime();

        // Assert
        long tokenDurationSeconds = Duration.between(issuedAt.toInstant(), expiration.toInstant()).toSeconds();
        assertEquals(SHORT_EXPIRATION_SECONDS, tokenDurationSeconds);
    }

    @Test
    void should_ParseToken_When_TokenIsValidAndNotRevoked() {
        // Arrange
        JwtProvider jwtProvider = buildJwtProviderForGenerateAndParseToken(DEFAULT_EXPIRATION_SECONDS);
        String token = jwtProvider.generateToken(USER_ID, EMAIL, UserRole.CLIENT);

        // Act
        Optional<JwtPrincipal> principal = jwtProvider.parseToken(token);

        // Assert
        assertTrue(principal.isPresent());
        assertEquals(USER_ID, principal.get().userId());
        assertEquals(EMAIL, principal.get().email());
        assertEquals(UserRole.CLIENT, principal.get().role());
    }

    @Test
    void should_ReturnEmpty_When_TokenIsRevoked() {
        // Arrange
        JwtProvider tokenGeneratorProvider = buildJwtProviderForGenerate(DEFAULT_EXPIRATION_SECONDS);
        String token = tokenGeneratorProvider.generateToken(USER_ID, EMAIL, UserRole.CLIENT);
        JwtProvider jwtProvider = buildJwtProviderForRevocationCheckOnly(DEFAULT_EXPIRATION_SECONDS);
        when(tokenRevocationService.isRevoked(token)).thenReturn(true);

        // Act
        Optional<JwtPrincipal> principal = jwtProvider.parseToken(token);

        // Assert
        assertTrue(principal.isEmpty());
    }

    @Test
    void should_ReturnEmpty_When_TokenIsExpired() {
        // Arrange
        JwtProvider jwtProvider = buildJwtProviderForGenerateAndParseToken(EXPIRED_EXPIRATION_SECONDS);
        String token = jwtProvider.generateToken(USER_ID, EMAIL, UserRole.CLIENT);

        // Act
        Optional<JwtPrincipal> principal = jwtProvider.parseToken(token);

        // Assert
        assertTrue(principal.isEmpty());
    }

    @Test
    void should_ReturnEmpty_When_TokenIsMalformed() {
        // Arrange
        JwtProvider jwtProvider = buildJwtProviderForRevocationCheckOnly(DEFAULT_EXPIRATION_SECONDS);

        // Act
        Optional<JwtPrincipal> principal = jwtProvider.parseToken(MALFORMED_TOKEN);

        // Assert
        assertTrue(principal.isEmpty());
    }

    @Test
    void should_ReturnEmpty_When_SignatureIsInvalid() {
        // Arrange
        KeyPair differentKeyPair = generateKeyPair();

        RsaKeyProvider signingKeyProvider = org.mockito.Mockito.mock(RsaKeyProvider.class);
        when(signingKeyProvider.getPrivateKey()).thenReturn((RSAPrivateKey) keyPair.getPrivate());
        when(tokenRevocationService.isRevoked(anyString())).thenReturn(false);
        JwtProvider signingProvider = new JwtProvider(signingKeyProvider, tokenRevocationService, DEFAULT_EXPIRATION_SECONDS);

        RsaKeyProvider verificationKeyProvider = org.mockito.Mockito.mock(RsaKeyProvider.class);
        when(verificationKeyProvider.getPublicKey()).thenReturn((RSAPublicKey) differentKeyPair.getPublic());
        JwtProvider verificationProvider = new JwtProvider(verificationKeyProvider, tokenRevocationService, DEFAULT_EXPIRATION_SECONDS);

        String token = signingProvider.generateToken(USER_ID, EMAIL, UserRole.CLIENT);

        // Act
        Optional<JwtPrincipal> principal = verificationProvider.parseToken(token);

        // Assert
        assertTrue(principal.isEmpty());
    }

    @Test
    void should_ReturnEmpty_When_SubjectIsInvalidUuid() throws Exception {
        // Arrange
        JwtProvider jwtProvider = buildJwtProviderForParseTokenOnly(DEFAULT_EXPIRATION_SECONDS);
        String token = buildSignedToken(INVALID_UUID_SUBJECT, EMAIL, List.of(UserRole.CLIENT.name()), Instant.now().plusSeconds(DEFAULT_EXPIRATION_SECONDS));

        // Act
        Optional<JwtPrincipal> principal = jwtProvider.parseToken(token);

        // Assert
        assertTrue(principal.isEmpty());
    }

    @Test
    void should_ReturnEmpty_When_RoleIsInvalid() throws Exception {
        // Arrange
        JwtProvider jwtProvider = buildJwtProviderForParseTokenOnly(DEFAULT_EXPIRATION_SECONDS);
        String token = buildSignedToken(USER_ID.toString(), EMAIL, List.of(INVALID_ROLE), Instant.now().plusSeconds(DEFAULT_EXPIRATION_SECONDS));

        // Act
        Optional<JwtPrincipal> principal = jwtProvider.parseToken(token);

        // Assert
        assertTrue(principal.isEmpty());
    }

    @Test
    void should_ReturnEmpty_When_RolesClaimIsEmpty() throws Exception {
        // Arrange
        JwtProvider jwtProvider = buildJwtProviderForParseTokenOnly(DEFAULT_EXPIRATION_SECONDS);
        String token = buildSignedToken(USER_ID.toString(), EMAIL, List.of(), Instant.now().plusSeconds(DEFAULT_EXPIRATION_SECONDS));

        // Act
        Optional<JwtPrincipal> principal = jwtProvider.parseToken(token);

        // Assert
        assertTrue(principal.isEmpty());
    }

    @Test
    void should_ReturnEmpty_When_SubjectIsMissing() throws Exception {
        // Arrange
        JwtProvider jwtProvider = buildJwtProviderForParseTokenOnly(DEFAULT_EXPIRATION_SECONDS);
        String token = buildSignedToken(TOKEN_WITHOUT_SUBJECT, EMAIL, List.of(UserRole.CLIENT.name()), Instant.now().plusSeconds(DEFAULT_EXPIRATION_SECONDS));

        // Act
        Optional<JwtPrincipal> principal = jwtProvider.parseToken(token);

        // Assert
        assertTrue(principal.isEmpty());
    }

    @Test
    void should_ReturnExpiration_When_TokenIsValid() {
        // Arrange
        JwtProvider tokenGeneratorProvider = buildJwtProviderForGenerate(DEFAULT_EXPIRATION_SECONDS);
        String token = tokenGeneratorProvider.generateToken(USER_ID, EMAIL, UserRole.CLIENT);
        JwtProvider jwtProvider = buildJwtProviderForExtractExpiration(DEFAULT_EXPIRATION_SECONDS);

        // Act
        Optional<Instant> expiration = jwtProvider.extractExpiration(token);

        // Assert
        assertTrue(expiration.isPresent());
        assertTrue(expiration.get().isAfter(Instant.now()));
    }

    @Test
    void should_ReturnEmptyExpiration_When_TokenIsMalformed() {
        // Arrange
        JwtProvider jwtProvider = new JwtProvider(rsaKeyProvider, tokenRevocationService, DEFAULT_EXPIRATION_SECONDS);

        // Act
        Optional<Instant> expiration = jwtProvider.extractExpiration(MALFORMED_TOKEN);

        // Assert
        assertTrue(expiration.isEmpty());
    }

    @Test
    void should_ReturnEmptyExpiration_When_SignatureIsInvalid() throws Exception {
        // Arrange
        JwtProvider jwtProvider = buildJwtProviderForExtractExpiration(DEFAULT_EXPIRATION_SECONDS);
        KeyPair otherKeyPair = generateKeyPair();

        SignedJWT unsignedJWT = buildUnsignedJwt(
                USER_ID.toString(),
                EMAIL,
                List.of(UserRole.CLIENT.name()),
                Instant.now().plusSeconds(DEFAULT_EXPIRATION_SECONDS)
        );
        unsignedJWT.sign(new RSASSASigner((RSAPrivateKey) otherKeyPair.getPrivate()));
        String token = unsignedJWT.serialize();

        // Act
        Optional<Instant> expiration = jwtProvider.extractExpiration(token);

        // Assert
        assertTrue(expiration.isEmpty());
    }

    @Test
    void should_ReturnEmptyExpiration_When_ExpirationClaimIsMissing() throws Exception {
        // Arrange
        JwtProvider jwtProvider = buildJwtProviderForExtractExpiration(DEFAULT_EXPIRATION_SECONDS);
        String token = buildSignedToken(USER_ID.toString(), EMAIL, List.of(UserRole.CLIENT.name()), null);

        // Act
        Optional<Instant> expiration = jwtProvider.extractExpiration(token);

        // Assert
        assertTrue(expiration.isEmpty());
    }

    private JwtProvider buildJwtProviderForGenerate(long expirationSeconds) {
        when(rsaKeyProvider.getPrivateKey()).thenReturn((RSAPrivateKey) keyPair.getPrivate());
        return new JwtProvider(rsaKeyProvider, tokenRevocationService, expirationSeconds);
    }

    private JwtProvider buildJwtProviderForRevocationCheckOnly(long expirationSeconds) {
        when(tokenRevocationService.isRevoked(anyString())).thenReturn(false);
        return new JwtProvider(rsaKeyProvider, tokenRevocationService, expirationSeconds);
    }

    private JwtProvider buildJwtProviderForParseTokenOnly(long expirationSeconds) {
        when(tokenRevocationService.isRevoked(anyString())).thenReturn(false);
        when(rsaKeyProvider.getPublicKey()).thenReturn((RSAPublicKey) keyPair.getPublic());
        return new JwtProvider(rsaKeyProvider, tokenRevocationService, expirationSeconds);
    }

    private JwtProvider buildJwtProviderForGenerateAndParseToken(long expirationSeconds) {
        when(tokenRevocationService.isRevoked(anyString())).thenReturn(false);
        when(rsaKeyProvider.getPrivateKey()).thenReturn((RSAPrivateKey) keyPair.getPrivate());
        when(rsaKeyProvider.getPublicKey()).thenReturn((RSAPublicKey) keyPair.getPublic());
        return new JwtProvider(rsaKeyProvider, tokenRevocationService, expirationSeconds);
    }

    private JwtProvider buildJwtProviderForExtractExpiration(long expirationSeconds) {
        when(rsaKeyProvider.getPublicKey()).thenReturn((RSAPublicKey) keyPair.getPublic());
        return new JwtProvider(rsaKeyProvider, tokenRevocationService, expirationSeconds);
    }

    private String buildSignedToken(String subject, String email, List<String> roles, Instant expiration) throws JOSEException {
        SignedJWT signedJWT = buildUnsignedJwt(subject, email, roles, expiration);
        signedJWT.sign(new RSASSASigner((RSAPrivateKey) keyPair.getPrivate()));
        return signedJWT.serialize();
    }

    private SignedJWT buildUnsignedJwt(String subject, String email, List<String> roles, Instant expiration) {
        JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder()
                .issuer(AuthConstants.JWT_ISSUER)
                .subject(subject)
                .claim(AuthConstants.JWT_CLAIM_EMAIL, email)
                .claim(AuthConstants.JWT_CLAIM_ROLES, roles)
                .issueTime(Date.from(Instant.now()));

        if (expiration != null) {
            claimsBuilder.expirationTime(Date.from(expiration));
        }

        return new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(AuthConstants.JWT_KEY_ID).build(), claimsBuilder.build());
    }

    private KeyPair generateKeyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance(AuthConstants.RSA_ALGORITHM);
            generator.initialize(AuthConstants.RSA_KEY_SIZE);
            return generator.generateKeyPair();
        } catch (Exception exception) {
            throw new IllegalStateException(exception);
        }
    }
}
