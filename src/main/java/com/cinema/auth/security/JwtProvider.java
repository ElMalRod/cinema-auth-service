package com.cinema.auth.security;

import com.cinema.auth.constants.AuthConstants;
import com.cinema.auth.domain.UserRole;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.UUID;

@Service
public class JwtProvider {

    private final RsaKeyProvider rsaKeyProvider;
    private final long expirationSeconds;

    public JwtProvider(
            RsaKeyProvider rsaKeyProvider,
            @Value("${auth.jwt.expiration-seconds:3600}") long expirationSeconds
    ) {
        this.rsaKeyProvider = rsaKeyProvider;
        this.expirationSeconds = expirationSeconds;
    }

    public String generateToken(UUID userId, String email, UserRole role) {
        JWTClaimsSet claims = buildClaims(userId, email, role);
        SignedJWT signedJwt = createSignedJwt(claims);
        signToken(signedJwt);
        return signedJwt.serialize();
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
        return new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claims);
    }

    private void signToken(SignedJWT signedJwt) {
        try {
            RSASSASigner signer = new RSASSASigner(rsaKeyProvider.getPrivateKey());
            signedJwt.sign(signer);
        } catch (JOSEException exception) {
            throw new IllegalStateException("No fue posible firmar el JWT", exception);
        }
    }
}
