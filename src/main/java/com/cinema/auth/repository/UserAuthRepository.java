package com.cinema.auth.repository;

import com.cinema.auth.domain.UserAuth;
import com.cinema.auth.domain.UserRole;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface UserAuthRepository extends JpaRepository<UserAuth, UUID> {

    Optional<UserAuth> findByEmail(String email);

    boolean existsByEmail(String email);

    boolean existsByRoleAndActiveTrue(UserRole role);

    List<UserAuth> findAllByOrderByCreatedAtDesc();
}