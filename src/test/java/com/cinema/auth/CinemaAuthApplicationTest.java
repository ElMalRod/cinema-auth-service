package com.cinema.auth;

import com.cinema.auth.service.AuthService;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;

@SpringBootTest(properties = {
        "spring.autoconfigure.exclude=org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration,org.springframework.boot.autoconfigure.orm.jpa.HibernateJpaAutoConfiguration,org.springframework.boot.autoconfigure.flyway.FlywayAutoConfiguration"
})
class CinemaAuthApplicationTest {

    @MockBean
    private AuthService authService;

    @Test
    void contextLoads() {
        // Arrange

        // Act

        // Assert
    }
}
