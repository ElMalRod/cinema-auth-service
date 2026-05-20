package com.cinema.auth.service;

import com.cinema.auth.constants.AuthConstants;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

import java.util.List;
import java.util.Map;

@Service
@Slf4j
@ConditionalOnProperty(prefix = "notifications.brevo", name = "enabled", havingValue = "true")
public class BrevoPasswordRecoveryNotificationService implements PasswordRecoveryNotificationService {

    private final RestClient restClient;
    private final String senderEmail;
    private final String senderName;

    public BrevoPasswordRecoveryNotificationService(
            @Value("${notifications.brevo.api-key}") String apiKey,
            @Value("${notifications.brevo.sender-email}") String senderEmail,
            @Value("${notifications.brevo.sender-name:Cinema}") String senderName
    ) {
        this.restClient = RestClient.builder()
                .baseUrl(AuthConstants.BREVO_BASE_URL)
                .defaultHeader(AuthConstants.BREVO_API_KEY_HEADER, apiKey)
                .defaultHeader("Content-Type", MediaType.APPLICATION_JSON_VALUE)
                .build();
        this.senderEmail = senderEmail;
        this.senderName = senderName;
    }

    @Override
    public void sendPasswordRecoveryEmail(String email, String recoveryUrl) {
        Map<String, Object> body = Map.of(
                "sender", Map.of("name", senderName, "email", senderEmail),
                "to", List.of(Map.of("email", email)),
                "subject", "Recuperacion de password - Cinema",
                "htmlContent", buildHtmlContent(recoveryUrl)
        );
        try {
            restClient.post().uri(AuthConstants.BREVO_EMAIL_PATH).body(body).retrieve().toBodilessEntity();
        } catch (Exception exception) {
            log.error("Error enviando correo de recuperacion a {}", email, exception);
            throw new IllegalStateException(AuthConstants.MESSAGE_RESET_MAIL_FAILURE, exception);
        }
    }

    private String buildHtmlContent(String recoveryUrl) {
        return "<p>Recibimos una solicitud para recuperar tu password.</p>"
                + "<p>Puedes cambiarla aqui: <a href=\"" + recoveryUrl + "\">Recuperar password</a></p>";
    }
}
