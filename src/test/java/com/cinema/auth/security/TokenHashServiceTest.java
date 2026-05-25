package com.cinema.auth.security;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class TokenHashServiceTest {

    private static final String TOKEN = "abc";
    private static final String EXPECTED_SHA256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    @Test
    void should_ReturnSha256Hash_When_TokenIsProvided() {
        // Arrange
        TokenHashService tokenHashService = new TokenHashService();

        // Act
        String hash = tokenHashService.hash(TOKEN);

        // Assert
        assertEquals(EXPECTED_SHA256, hash);
    }
}
