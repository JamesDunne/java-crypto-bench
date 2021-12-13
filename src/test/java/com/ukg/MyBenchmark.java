package com.ukg;

import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.infra.Blackhole;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.concurrent.TimeUnit;

public class MyBenchmark {
    private static final byte[] plainText;

    static {
        plainText = new byte[1 << 20];

        SecureRandom random = new SecureRandom();
        random.nextBytes(plainText);
    }

    @State(Scope.Thread)
    public static class AESGCM256 {
        SecureRandom secureRandom = new SecureRandom();
        private Cipher cipher;

        private byte[] iv;

        private SecretKey secretKey;

        @Setup()
        public void setup() throws NoSuchAlgorithmException, NoSuchPaddingException {
            // AES-GCM-256 (32 bytes = 256 bits)
            byte[] key = new byte[32];
            secureRandom.nextBytes(key);
            secretKey = new SecretKeySpec(key, "AES");

            iv = new byte[12];
            secureRandom.nextBytes(iv);

            cipher = Cipher.getInstance("AES/GCM/NoPadding");
        }

        @Benchmark
        @BenchmarkMode(Mode.Throughput)
        @Fork(1)
        @Threads(1)
        @Warmup(iterations = 2, time = 5, timeUnit = TimeUnit.SECONDS)
        @Measurement(iterations = 10, time = 5, timeUnit = TimeUnit.SECONDS)
        public void encrypt(Blackhole blackhole) throws IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException {
            iv[0]++;
            GCMParameterSpec parameterSpec = new GCMParameterSpec(128, iv); //128 bit auth tag length
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);

            byte[] cipherText = cipher.doFinal(plainText);
            //blackhole.consume(cipherText);

            ByteBuffer byteBuffer = ByteBuffer.allocate(iv.length + cipherText.length);
            byteBuffer.put(iv);
            byteBuffer.put(cipherText);
            byte[] cipherMessage = byteBuffer.array();

            blackhole.consume(cipherMessage);
        }
    }

    @State(Scope.Thread)
    public static class HMAC256 {
        SecureRandom secureRandom = new SecureRandom();
        private Mac mac;
        private SecretKeySpec secretKey;

        @Setup
        public void setup() throws NoSuchAlgorithmException, InvalidKeyException {
            byte[] key = new byte[32];
            secureRandom.nextBytes(key);

            mac = Mac.getInstance("HmacSHA256");

            secretKey = new SecretKeySpec(key, "HmacSHA256");
            mac.init(secretKey);
        }

        @Benchmark
        @BenchmarkMode(Mode.Throughput)
        @Fork(1)
        @Threads(1)
        @Warmup(iterations = 2, time = 5, timeUnit = TimeUnit.SECONDS)
        @Measurement(iterations = 10, time = 5, timeUnit = TimeUnit.SECONDS)
        public void hash(Blackhole blackhole) {
            byte[] finalHash = mac.doFinal(plainText);

            blackhole.consume(finalHash);
        }
    }
}
