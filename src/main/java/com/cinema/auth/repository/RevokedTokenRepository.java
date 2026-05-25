package com.cinema.auth.repository;

import com.cinema.auth.domain.RevokedToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.UUID;

public interface RevokedTokenRepository extends JpaRepository<RevokedToken, UUID> {

    boolean existsByTokenHash(String tokenHash);

    @Modifying
    @Transactional
    void deleteByExpiresAtBefore(LocalDateTime now);
}
