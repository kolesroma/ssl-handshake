package org.security.kolesnyk.rgr;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;

public class SecureFileTransferServiceImpl {
    public static final String MESSAGE = "Hello";

    private static final String PROVIDER_BOUNCY_CASTLE = "BC";
    private static final String ALGORITHM_RSA = "RSA";
    private static final String ALGORITHM_AES = "AES";
    private static final String CYPHER_TRANSFORMATION_RAS_ECB = "RSA/ECB/PKCS1Padding";
    private static final String CYPHER_TRANSFORMATION_AES_CBC = "AES/CBC/PKCS5Padding";

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        KeyPair clientRSAKeyPair = generateRSAKeyPair();
        KeyPair serverRSAKeyPair = generateRSAKeyPair();
        PublicKey clientPublicKey = clientRSAKeyPair.getPublic();
        PublicKey serverPublicKey = serverRSAKeyPair.getPublic();

        SecretKey aesKey = generateAESKey();
        byte[] encryptedAESKey = encryptWithRSA(serverPublicKey, aesKey.getEncoded());

        byte[] decryptedAESKeyBytes = decryptWithRSA(serverRSAKeyPair.getPrivate(), encryptedAESKey);
        SecretKeySpec decryptedAESKey = new SecretKeySpec(decryptedAESKeyBytes, ALGORITHM_AES);

        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[16];
        random.nextBytes(iv);
        byte[] encryptedMessage = encryptWithAES(aesKey, MESSAGE.getBytes(StandardCharsets.UTF_8), iv);

        byte[] decryptedMessageBytes = decryptWithAES(decryptedAESKey, encryptedMessage, iv);
        String decryptedMessage = new String(decryptedMessageBytes, StandardCharsets.UTF_8);
        System.out.println("Original message: " + MESSAGE);
        System.out.println("clientPublicKey = " + clientPublicKey);
        System.out.println("encryptedAESKey = " + Arrays.toString(encryptedAESKey));
        System.out.println("Decrypted message: " + decryptedMessage);
    }

    public static KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM_RSA, PROVIDER_BOUNCY_CASTLE);
            keyPairGenerator.initialize(2048);
            return keyPairGenerator.generateKeyPair();
        } catch (NoSuchProviderException e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] encryptWithRSA(PublicKey receiverPublicKey, byte[] input) throws Exception {
        Cipher cipher = Cipher.getInstance(CYPHER_TRANSFORMATION_RAS_ECB, PROVIDER_BOUNCY_CASTLE);
        cipher.init(Cipher.ENCRYPT_MODE, receiverPublicKey);
        return cipher.doFinal(input);
    }

    public static byte[] decryptWithRSA(PrivateKey receiverPrivateKey, byte[] encrypted) throws Exception {
        Cipher cipher = Cipher.getInstance(CYPHER_TRANSFORMATION_RAS_ECB, PROVIDER_BOUNCY_CASTLE);
        cipher.init(Cipher.DECRYPT_MODE, receiverPrivateKey);
        return cipher.doFinal(encrypted);
    }

    public static SecretKey generateAESKey() throws NoSuchAlgorithmException {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM_AES, PROVIDER_BOUNCY_CASTLE);
            keyGenerator.init(128);
            return keyGenerator.generateKey();
        } catch (NoSuchProviderException e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] encryptWithAES(SecretKey secretKey, byte[] data, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance(CYPHER_TRANSFORMATION_AES_CBC);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
        return cipher.doFinal(data);
    }

    public static byte[] decryptWithAES(SecretKey secretKey, byte[] encryptedData, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance(CYPHER_TRANSFORMATION_AES_CBC);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
        return cipher.doFinal(encryptedData);
    }
}
