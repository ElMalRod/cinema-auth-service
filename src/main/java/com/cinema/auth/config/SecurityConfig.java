package com.cinema.auth.config;

import com.cinema.auth.security.JwtAuthenticationFilter;
import org.apache.kafka.clients.admin.NewTopic;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.kafka.config.TopicBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
                                                   JwtAuthenticationFilter jwtAuthenticationFilter) throws Exception {
        http.csrf(csrf -> csrf.disable());
        http.httpBasic(httpBasic -> httpBasic.disable());
        http.formLogin(formLogin -> formLogin.disable());
        http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        http.exceptionHandling(exception -> exception
                .authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))
                .accessDeniedHandler((request, response, denied) -> {
                    if (request.getHeader("Authorization") == null) {
                        response.setStatus(HttpStatus.UNAUTHORIZED.value());
                        return;
                    }
                    response.setStatus(HttpStatus.FORBIDDEN.value());
                }));
        http.authorizeHttpRequests(authorize -> authorize
                .requestMatchers(HttpMethod.POST, "/auth/login", "/auth/register", "/auth/forgot-password", "/auth/reset-password").permitAll()
                .requestMatchers(HttpMethod.GET, "/auth/public-key", "/.well-known/jwks.json", "/swagger-ui.html", "/swagger-ui/**", "/v3/api-docs/**").permitAll()
                .requestMatchers(HttpMethod.GET, "/auth/exists-admin", "/auth/admin/list").permitAll()
                .requestMatchers(HttpMethod.POST, "/auth/admin/create-user").permitAll()
                .requestMatchers(HttpMethod.PATCH, "/auth/admin/activate/**", "/auth/admin/deactivate/**").permitAll()
                .requestMatchers(HttpMethod.PATCH, "/auth/deactivate/**", "/auth/activate/**").hasRole("SYSTEM_ADMIN")
                .requestMatchers(HttpMethod.GET, "/auth/me").authenticated()
                .requestMatchers(HttpMethod.POST, "/auth/logout", "/auth/change-password").authenticated()
                .anyRequest().authenticated());
        http.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    @Bean
    public NewTopic userEventsTopic() {
        return TopicBuilder
            .name("user-events")
            .partitions(1)
            .replicas(1)
            .build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
