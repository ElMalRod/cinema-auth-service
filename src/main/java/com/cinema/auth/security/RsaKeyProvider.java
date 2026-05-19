package com.cinema.auth.security;

import com.cinema.auth.constants.AuthConstants;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

@Component
public class RsaKeyProvider {

    private final KeyPair keyPair;

    public RsaKeyProvider() {
        this.keyPair = generateKeyPair();
    }

    public PublicKey getPublicKey() {
        return keyPair.getPublic();
    }

    public PrivateKey getPrivateKey() {
        return keyPair.getPrivate();
    }

    public String getPublicKeyPem() {
        String encodedKey = encodeToPem(getPublicKey().getEncoded());
        return AuthConstants.PEM_PUBLIC_KEY_BEGIN + AuthConstants.PEM_LINE_SEPARATOR
                + encodedKey + AuthConstants.PEM_LINE_SEPARATOR
                + AuthConstants.PEM_PUBLIC_KEY_END;
    }

    private KeyPair generateKeyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance(AuthConstants.RSA_ALGORITHM);
            generator.initialize(AuthConstants.RSA_KEY_SIZE);
            return generator.generateKeyPair();
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("No fue posible generar el par de llaves RSA", exception);
        }
    }

    private String encodeToPem(byte[] keyBytes) {
        byte[] lineBreak = AuthConstants.PEM_LINE_SEPARATOR.getBytes(StandardCharsets.UTF_8);
        return Base64.getMimeEncoder(64, lineBreak).encodeToString(keyBytes);
    }
}
