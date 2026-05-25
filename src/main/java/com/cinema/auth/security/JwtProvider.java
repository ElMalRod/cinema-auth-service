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
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.text.ParseException;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
public class JwtProvider {

    private final RsaKeyProvider rsaKeyProvider;
    private final TokenRevocationService tokenRevocationService;
    private final long expirationSeconds;

    public JwtProvider(
            RsaKeyProvider rsaKeyProvider,
            TokenRevocationService tokenRevocationService,
            @Value("${auth.jwt.expiration-seconds:3600}") long expirationSeconds
    ) {
        this.rsaKeyProvider = rsaKeyProvider;
        this.tokenRevocationService = tokenRevocationService;
        this.expirationSeconds = expirationSeconds;
    }

    public String generateToken(UUID userId, String email, UserRole role) {
        JWTClaimsSet claims = buildClaims(userId, email, role);
        SignedJWT signedJwt = createSignedJwt(claims);
        signToken(signedJwt);
        return signedJwt.serialize();
    }

    public Optional<JwtPrincipal> parseToken(String token) {
        if (tokenRevocationService.isRevoked(token)) {
            return Optional.empty();
        }
        return parseSignedToken(token)
                .filter(this::isSignatureValid)
                .filter(this::isNotExpired)
                .flatMap(this::extractPrincipal);
    }

    public Optional<Instant> extractExpiration(String token) {
        return parseSignedToken(token)
                .filter(this::isSignatureValid)
                .flatMap(this::toExpiration);
    }

    private JWTClaimsSet buildClaims(UUID userId, String email, UserRole role) {
        Instant issuedAt = Instant.now();
        Instant expiresAt = issuedAt.plusSeconds(expirationSeconds);
        return new JWTClaimsSet.Builder()
                .issuer(AuthConstants.JWT_ISSUER)
                .subject(userId.toString())
                .claim(AuthConstants.JWT_CLAIM_EMAIL, email)
                .claim(AuthConstants.JWT_CLAIM_ROLES, List.of(role.name()))
                .issueTime(Date.from(issuedAt))
                .expirationTime(Date.from(expiresAt))
                .build();
    }

    private SignedJWT createSignedJwt(JWTClaimsSet claims) {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .keyID(AuthConstants.JWT_KEY_ID)
                .build();
        return new SignedJWT(header, claims);
    }

    private void signToken(SignedJWT signedJwt) {
        try {
            RSASSASigner signer = new RSASSASigner(rsaKeyProvider.getPrivateKey());
            signedJwt.sign(signer);
        } catch (JOSEException exception) {
            throw new IllegalStateException("No fue posible firmar el JWT", exception);
        }
    }

    private Optional<SignedJWT> parseSignedToken(String token) {
        try {
            return Optional.of(SignedJWT.parse(token));
        } catch (ParseException exception) {
            return Optional.empty();
        }
    }

    private boolean isSignatureValid(SignedJWT signedJWT) {
        try {
            return signedJWT.verify(new RSASSAVerifier(rsaKeyProvider.getPublicKey()));
        } catch (JOSEException exception) {
            return false;
        }
    }

    private boolean isNotExpired(SignedJWT signedJWT) {
        return toExpiration(signedJWT)
                .map(expiration -> expiration.isAfter(Instant.now()))
                .orElse(false);
    }

    private Optional<Instant> toExpiration(SignedJWT signedJWT) {
        try {
            Date expiration = signedJWT.getJWTClaimsSet().getExpirationTime();
            return expiration == null ? Optional.empty() : Optional.of(expiration.toInstant());
        } catch (ParseException exception) {
            return Optional.empty();
        }
    }

    private Optional<JwtPrincipal> extractPrincipal(SignedJWT signedJWT) {
        try {
            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
            return mapPrincipal(claims.getSubject(), claims.getStringClaim(AuthConstants.JWT_CLAIM_EMAIL),
                    claims.getStringListClaim(AuthConstants.JWT_CLAIM_ROLES));
        } catch (ParseException exception) {
            return Optional.empty();
        }
    }

    private Optional<JwtPrincipal> mapPrincipal(String subject, String email, List<String> roles) {
        if (subject == null || email == null || roles == null || roles.isEmpty()) {
            return Optional.empty();
        }
        try {
            UUID userId = UUID.fromString(subject);
            UserRole role = UserRole.valueOf(roles.getFirst());
            return Optional.of(new JwtPrincipal(userId, email, role));
        } catch (IllegalArgumentException exception) {
            return Optional.empty();
        }
    }
}
