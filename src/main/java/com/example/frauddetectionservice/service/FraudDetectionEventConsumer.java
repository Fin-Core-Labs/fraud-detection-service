package com.example.frauddetectionservice.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.messaging.handler.annotation.Payload;
import org.springframework.stereotype.Service;

import java.util.Map;

@Slf4j
@Service
@RequiredArgsConstructor
public class FraudDetectionEventConsumer {

    private final FraudDetectionService fraudDetectionService;

    /*
     * Listen to transaction.initiated topic.
     * Every transaction goes through fraud checks before completing.
     */
    @KafkaListener(
            topics = "transaction.initiated",
            groupId = "fraud.detection-group"
    )
    public void consumeTransactionInitiated(
            @Payload Map<String, Object> payload
    ) {
        log.info(
                "Received transaction for fraud check: {}",
                payload.get("transactionId")
        );

        try {
            fraudDetectionService.checkTransaction(payload);
        } catch (Exception e) {
            log.error(
                    "Failed to process transaction for fraud detection: {}",
                    payload.get("transactionId"),
                    e
            );
        }
    }
}