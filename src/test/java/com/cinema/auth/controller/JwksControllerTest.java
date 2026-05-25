package com.cinema.auth.controller;

import com.cinema.auth.security.RsaKeyProvider;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class JwksControllerTest {

    private static final String EXPECTED_KEY_ID = "cinema-key";

    @Test
    void should_ReturnValidJwksDocument_When_PublicKeyIsAvailable() throws Exception {
        // Arrange
        RsaKeyProvider rsaKeyProvider = mock(RsaKeyProvider.class);
        when(rsaKeyProvider.getPublicKey()).thenReturn(generatePublicKey());
        JwksController jwksController = new JwksController(rsaKeyProvider);

        // Act
        String body = jwksController.jwks().getBody();

        // Assert
        JWKSet jwkSet = JWKSet.parse(body);
        RSAKey key = (RSAKey) jwkSet.getKeys().getFirst();

        assertNotNull(body);
        assertEquals(EXPECTED_KEY_ID, key.getKeyID());
        assertEquals(KeyUse.SIGNATURE, key.getKeyUse());
        assertEquals(JWSAlgorithm.RS256, key.getAlgorithm());
    }

    private RSAPublicKey generatePublicKey() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();
        return (RSAPublicKey) keyPair.getPublic();
    }
}
