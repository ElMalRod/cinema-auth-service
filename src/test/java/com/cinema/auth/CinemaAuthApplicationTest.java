package com.cinema.auth;

import com.cinema.auth.security.JwtAuthenticationFilter;
import com.cinema.auth.security.JwtProvider;
import com.cinema.auth.service.AuthService;
import com.cinema.auth.service.PasswordResetService;
import com.cinema.auth.service.TokenRevocationService;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;

@SpringBootTest(properties = {
        "spring.autoconfigure.exclude=org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration,org.springframework.boot.autoconfigure.orm.jpa.HibernateJpaAutoConfiguration,org.springframework.boot.autoconfigure.flyway.FlywayAutoConfiguration"
})
class CinemaAuthApplicationTest {

    @MockBean
    private AuthService authService;

    @MockBean
    private JwtProvider jwtProvider;

    @MockBean
    private JwtAuthenticationFilter jwtAuthenticationFilter;

    @MockBean
    private PasswordResetService passwordResetService;

    @MockBean
    private TokenRevocationService tokenRevocationService;

    @Test
    void contextLoads() {
        // Arrange

        // Act

        // Assert
    }
}
