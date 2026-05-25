package com.cinema.auth.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.kafka.core.KafkaTemplate;

import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class UserEventPublisherTest {

    private static final String TOPIC = "user-events";
    private static final String USER_CREATED_EVENT = "USER_CREATED";
    private static final String CINEMA_ADMIN_CREATED_EVENT = "CINEMA_ADMIN_CREATED";
    private static final String ADVERTISER_CREATED_EVENT = "ADVERTISER_CREATED";
    private static final UUID USER_ID = UUID.fromString("00000000-0000-0000-0000-000000000601");
    private static final String USER_NAME = "Cinema User";
    private static final String USER_PHONE = "5556000";
    private static final String COMPANY_NAME = "Cinema Group";

    @Mock
    private KafkaTemplate<String, Object> kafkaTemplate;

    private UserEventPublisher userEventPublisher;

    @BeforeEach
    void setUp() {
        userEventPublisher = new UserEventPublisher(kafkaTemplate);
    }

    @Test
    void should_PublishUserCreatedEvent_When_PublishUserCreatedIsCalled() {
        // Arrange

        // Act
        userEventPublisher.publishUserCreated(USER_ID, USER_NAME, USER_PHONE);

        // Assert
        ArgumentCaptor<Map<String, Object>> payloadCaptor = ArgumentCaptor.forClass(Map.class);
        verify(kafkaTemplate).send(org.mockito.ArgumentMatchers.eq(TOPIC), payloadCaptor.capture());

        assertEquals(USER_CREATED_EVENT, payloadCaptor.getValue().get("event"));
        assertEquals(USER_ID.toString(), payloadCaptor.getValue().get("id"));
        assertEquals(USER_NAME, payloadCaptor.getValue().get("name"));
        assertEquals(USER_PHONE, payloadCaptor.getValue().get("phone"));
    }

    @Test
    void should_PublishCinemaAdminCreatedEventWithCompany_When_PublishCinemaAdminCreatedIsCalled() {
        // Arrange

        // Act
        userEventPublisher.publishCinemaAdminCreated(USER_ID, USER_NAME, USER_PHONE, COMPANY_NAME);

        // Assert
        ArgumentCaptor<Map<String, Object>> payloadCaptor = ArgumentCaptor.forClass(Map.class);
        verify(kafkaTemplate).send(org.mockito.ArgumentMatchers.eq(TOPIC), payloadCaptor.capture());

        assertEquals(CINEMA_ADMIN_CREATED_EVENT, payloadCaptor.getValue().get("event"));
        assertEquals(COMPANY_NAME, payloadCaptor.getValue().get("companyName"));
    }

    @Test
    void should_PublishAdvertiserCreatedEvent_When_PublishAdvertiserCreatedIsCalled() {
        // Arrange

        // Act
        userEventPublisher.publishAdvertiserCreated(USER_ID, USER_NAME, USER_PHONE);

        // Assert
        ArgumentCaptor<Map<String, Object>> payloadCaptor = ArgumentCaptor.forClass(Map.class);
        verify(kafkaTemplate).send(org.mockito.ArgumentMatchers.eq(TOPIC), payloadCaptor.capture());
        assertEquals(ADVERTISER_CREATED_EVENT, payloadCaptor.getValue().get("event"));
    }
}
