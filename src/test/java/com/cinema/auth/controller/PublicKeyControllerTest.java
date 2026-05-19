package com.cinema.auth.controller;

import com.cinema.auth.security.RsaKeyProvider;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class PublicKeyControllerTest {

    @Test
    void shouldReturnPublicKeyPem() {
        // Arrange
        RsaKeyProvider keyProvider = mock(RsaKeyProvider.class);
        when(keyProvider.getPublicKeyPem()).thenReturn("PUBLIC_KEY_PEM");
        PublicKeyController controller = new PublicKeyController(keyProvider);

        // Act
        String response = controller.getPublicKey().getBody();

        // Assert
        assertEquals("PUBLIC_KEY_PEM", response);
    }
}
