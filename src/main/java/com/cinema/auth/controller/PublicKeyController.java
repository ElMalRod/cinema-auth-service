package com.cinema.auth.controller;

import com.cinema.auth.constants.AuthConstants;
import com.cinema.auth.security.RsaKeyProvider;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class PublicKeyController {

    private final RsaKeyProvider rsaKeyProvider;

    public PublicKeyController(RsaKeyProvider rsaKeyProvider) {
        this.rsaKeyProvider = rsaKeyProvider;
    }

    @GetMapping(value = AuthConstants.PUBLIC_KEY_ENDPOINT, produces = MediaType.TEXT_PLAIN_VALUE)
    public ResponseEntity<String> getPublicKey() {
        return ResponseEntity.ok(rsaKeyProvider.getPublicKeyPem());
    }
}
