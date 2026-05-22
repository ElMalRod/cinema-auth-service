package com.cinema.auth.service;

import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Service
public class UserEventPublisher {

    private static final String USER_EVENTS_TOPIC = "user-events";

    private final KafkaTemplate<String, Object> kafkaTemplate;

    public UserEventPublisher(KafkaTemplate<String, Object> kafkaTemplate) {
        this.kafkaTemplate = kafkaTemplate;
    }

    public void publishUserCreated(UUID userId, String name, String phone) {
        Map<String, Object> payload = basePayload("USER_CREATED", userId, name, phone);
        kafkaTemplate.send(USER_EVENTS_TOPIC, payload);
    }

    public void publishCinemaAdminCreated(UUID userId, String name, String phone, String companyName) {
        Map<String, Object> payload = basePayload("CINEMA_ADMIN_CREATED", userId, name, phone);
        payload.put("companyName", companyName);
        kafkaTemplate.send(USER_EVENTS_TOPIC, payload);
    }

    public void publishAdvertiserCreated(UUID userId, String name, String phone) {
        Map<String, Object> payload = basePayload("ADVERTISER_CREATED", userId, name, phone);
        kafkaTemplate.send(USER_EVENTS_TOPIC, payload);
    }

    private Map<String, Object> basePayload(String event, UUID userId, String name, String phone) {
        Map<String, Object> payload = new HashMap<>();
        payload.put("event", event);
        payload.put("id", userId.toString());
        payload.put("name", name);
        payload.put("phone", phone);
        return payload;
    }
}
