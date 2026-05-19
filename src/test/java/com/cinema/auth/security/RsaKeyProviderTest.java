package com.cinema.auth.security;

import com.cinema.auth.constants.AuthConstants;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RsaKeyProviderTest {

    @Test
    void shouldGenerateRsaKeysAndPemPublicKey() {
        // Arrange
        RsaKeyProvider provider = new RsaKeyProvider();

        // Act
        String publicKeyPem = provider.getPublicKeyPem();

        // Assert
        assertNotNull(provider.getPrivateKey());
        assertNotNull(provider.getPublicKey());
        assertTrue(publicKeyPem.startsWith(AuthConstants.PEM_PUBLIC_KEY_BEGIN));
        assertTrue(publicKeyPem.endsWith(AuthConstants.PEM_PUBLIC_KEY_END));
    }
}
