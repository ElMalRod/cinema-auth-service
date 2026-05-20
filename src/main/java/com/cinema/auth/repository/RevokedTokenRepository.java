package com.cinema.auth.repository;

import com.cinema.auth.domain.RevokedToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.LocalDateTime;
import java.util.UUID;

public interface RevokedTokenRepository extends JpaRepository<RevokedToken, UUID> {

    boolean existsByTokenHash(String tokenHash);

    void deleteByExpiresAtBefore(LocalDateTime now);
}
