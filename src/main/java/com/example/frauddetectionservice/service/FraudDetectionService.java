package com.example.frauddetectionservice.service;

import com.example.frauddetectionservice.client.AccountServiceClient;
import com.example.frauddetectionservice.model.FraudCheckResult;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Service;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

@Service
@Slf4j
@RequiredArgsConstructor
public class FraudDetectionService {

    private static final String VERIFICATION_REQUIRED_TOPIC = "verification.required";
    private static final String FRAUD_CHECK_CLEAN_RESULT_TOPIC = "fraud.check.clean";

    private final AccountServiceClient accountServiceClient;
    private final KafkaTemplate<String, Object> kafkaTemplate;
    private final RedisTemplate<String, String> redisTemplate;

    @Value("${fraud.max-transactions-per-minute}")
    private int maxTransactionsPerMinute;

    @Value("${fraud.suspicious-amount-multiplier}")
    private double suspiciousAmountMultiplier;

    @Value("${fraud.max-balance-percentage}")
    private double maxBalancePercentage;

    public void checkTransaction(Map<String, Object> payload) {
        String transactionId = (String) payload.get("transactionId");
        String accountNumber = (String) payload.get("accountNumber");
        BigDecimal amount = new BigDecimal(payload.get("amount").toString());

        // Fetch real balance from account service.
        BigDecimal senderBalance = accountServiceClient.getBalance(accountNumber);

        log.info(
                "Checking transaction: {} account: {} amount: {} balance: {}",
                transactionId,
                accountNumber,
                amount,
                senderBalance
        );

        FraudCheckResult result = performFraudChecks(
                accountNumber,
                amount,
                senderBalance
        );

        if (result.isFraud()) {
            log.info(
                    "Suspicious activity detected - account: {} reason: {} - requesting OTP verification",
                    accountNumber,
                    result.getReason()
            );

            Map<String, Object> verificationEvent = new HashMap<>();
            verificationEvent.put("transactionId", transactionId);
            verificationEvent.put("accountNumber", accountNumber);
            verificationEvent.put("amount", amount);
            verificationEvent.put("reason", result.getReason());

            kafkaTemplate.send(
                    VERIFICATION_REQUIRED_TOPIC,
                    transactionId,
                    verificationEvent
            );
        } else {
            log.info(
                    "Transaction passed fraud checks - transactionId: {}",
                    transactionId
            );

            Map<String, Object> transactionCleanEvent = new HashMap<>();
            transactionCleanEvent.put("transactionId", transactionId);
            transactionCleanEvent.put("isFraud", false);
            transactionCleanEvent.put("reason", null);

            kafkaTemplate.send(
                    FRAUD_CHECK_CLEAN_RESULT_TOPIC,
                    transactionId,
                    transactionCleanEvent
            );
        }
    }

    private FraudCheckResult performFraudChecks(
            String accountNumber,
            BigDecimal amount,
            BigDecimal senderBalance
    ) {
        // Pattern 1: Velocity Check
        if (isVelocityExceeded(accountNumber)) {
            return new FraudCheckResult(
                    true,
                    "Too many transactions in one minute - velocity limit exceeded"
            );
        }

        // Pattern 2: Amount Check
        if (isAmountSuspicious(accountNumber, amount)) {
            return new FraudCheckResult(
                    true,
                    "Unusual transaction amount - exceeds the allowed average multiplier"
            );
        }

        // Pattern 3: Balance Check
        if (senderBalance.compareTo(BigDecimal.ZERO) > 0
                && isBalanceCheckFailed(senderBalance, amount)) {

            return new FraudCheckResult(
                    true,
                    "Transaction amount exceeds the allowed percentage of the account balance"
            );
        }

        return new FraudCheckResult(false, null);
    }

    private boolean isVelocityExceeded(String accountNumber) {
        String key = "fraud:velocity:" + accountNumber;

        Long count = redisTemplate.opsForValue().increment(key);

        if (count != null && count == 1) {
            redisTemplate.expire(key, 1, TimeUnit.MINUTES);
        }

        log.info(
                "Velocity check - account: {} count: {}/{}",
                accountNumber,
                count,
                maxTransactionsPerMinute
        );

        return count != null && count > maxTransactionsPerMinute;
    }

    private boolean isAmountSuspicious(
            String accountNumber,
            BigDecimal amount
    ) {
        String avgKey = "fraud:avg_amount:" + accountNumber;

        String avgStr = redisTemplate.opsForValue().get(avgKey);

        if (avgStr == null) {
            redisTemplate.opsForValue().set(avgKey, amount.toString());
            return false;
        }

        BigDecimal avgAmount = new BigDecimal(avgStr);

        BigDecimal threshold = avgAmount.multiply(
                BigDecimal.valueOf(suspiciousAmountMultiplier)
        );

        boolean suspicious = amount.compareTo(threshold) > 0;

        BigDecimal newAvg = avgAmount
                .add(amount)
                .divide(BigDecimal.valueOf(2), 2, RoundingMode.HALF_UP);

        redisTemplate.opsForValue().set(
                avgKey,
                newAvg.toString()
        );

        log.info(
                "Amount check - account: {} amount: {} threshold: {} multiplier: {} suspicious: {}",
                accountNumber,
                amount,
                threshold,
                suspiciousAmountMultiplier,
                suspicious
        );

        return suspicious;
    }

    private boolean isBalanceCheckFailed(
            BigDecimal senderBalance,
            BigDecimal amount
    ) {
        BigDecimal maxAllowed = senderBalance.multiply(
                BigDecimal.valueOf(maxBalancePercentage)
        );

        boolean suspicious = amount.compareTo(maxAllowed) > 0;

        log.info(
                "Balance check - amount: {} maxAllowed: {} suspicious: {}",
                amount,
                maxAllowed,
                suspicious
        );

        return suspicious;
    }
}