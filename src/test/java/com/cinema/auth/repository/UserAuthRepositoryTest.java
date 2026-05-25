package com.cinema.auth.repository;

import com.cinema.auth.domain.UserAuth;
import com.cinema.auth.domain.UserRole;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;

import java.time.LocalDateTime;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DataJpaTest(properties = {
        "spring.flyway.enabled=false",
        "spring.jpa.hibernate.ddl-auto=create-drop"
})
class UserAuthRepositoryTest {

    @Autowired
    private UserAuthRepository repository;

    @Test
    void shouldSaveUserAuth() {
        // Arrange
        UserAuth user = buildUser("admin@test.com", UserRole.SYSTEM_ADMIN);

        // Act
        UserAuth savedUser = repository.save(user);

        // Assert
        assertNotNull(savedUser.getId());
        assertEquals("admin@test.com", savedUser.getEmail());
        assertEquals(UserRole.SYSTEM_ADMIN, savedUser.getRole());
        assertTrue(repository.existsByEmail("admin@test.com"));
    }

    @Test
    void shouldFindByEmail() {
        // Arrange
        UserAuth user = buildUser("client@test.com", UserRole.CLIENT);
        repository.save(user);

        // Act
        Optional<UserAuth> foundUser = repository.findByEmail("client@test.com");

        // Assert
        assertTrue(foundUser.isPresent());
        assertEquals("client@test.com", foundUser.get().getEmail());
        assertEquals(UserRole.CLIENT, foundUser.get().getRole());
    }

    private UserAuth buildUser(String email, UserRole role) {
        LocalDateTime now = LocalDateTime.now();
        return UserAuth.builder()
                .email(email)
                .passwordHash("hashed-password")
                .role(role)
                .active(true)
                .createdAt(now)
                .updatedAt(now)
                .build();
    }
}
