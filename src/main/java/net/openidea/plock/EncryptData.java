package net.openidea.plock;

import org.apache.maven.plugin.logging.Log;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;

public class EncryptData {

    public static final byte[] MAGIC_NUMBER = new byte[] {'P', 'L', 'O', 'C', 'K'};

    private static SecretKey generateAESKey(final Log log) {
        final KeyGenerator keyGenerator;

        try {
            keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(256);
            return keyGenerator.generateKey();
        } catch (NoSuchAlgorithmException e) {
            log.error(e);
        }
        return null;
    }

    private static byte[] encryptData(final Log log, final byte[] bytes, final SecretKey secretKey) {
        final Cipher cipher;

        if (bytes == null || secretKey == null)
            return null;
        try {
            cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            return cipher.doFinal(bytes);
        } catch (Exception e) {
            log.error(e);
        }
        return null;
    }

    private static byte[] encryptAESKey(final Log log, final SecretKey secretKey, final RSAPrivateKey rsaPrivateKey) {
        final Cipher cipher;

        if (secretKey == null || rsaPrivateKey == null)
            return null;
        try {
            cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, rsaPrivateKey);
            return cipher.doFinal(secretKey.getEncoded());
        } catch (Exception e) {
            log.error(e);
        }
        return null;
    }

    public static byte[] encrypt(final Log log, final byte[] bytes, final RSAPrivateKey rsaPrivateKey) {
        final SecretKey aesKey = generateAESKey(log);
        final byte[] encryptedBytes = encryptData(log, bytes, aesKey);
        final byte[] encryptedAesKey = encryptAESKey(log, aesKey, rsaPrivateKey);
        final ByteBuffer byteBuffer;

        if (encryptedBytes == null || encryptedAesKey == null)
            return null;
        byteBuffer = ByteBuffer.allocate(4 + encryptedAesKey.length + encryptedBytes.length);
        byteBuffer.putInt(encryptedAesKey.length);
        byteBuffer.put(encryptedAesKey);
        byteBuffer.put(encryptedBytes);
        return byteBuffer.array();
    }

    public static void encryptFile(final Log log, final Path filePath, final RSAPrivateKey rsaPrivateKey) throws IOException {
        final byte[] fileEncryptBytes;
        final ByteBuffer byteBuffer;

        if (filePath == null || rsaPrivateKey == null)
            return;
        fileEncryptBytes = encrypt(log, Files.readAllBytes(filePath), rsaPrivateKey);
        if (fileEncryptBytes == null)
            return;
        byteBuffer = ByteBuffer.allocate(4 + fileEncryptBytes.length);
        byteBuffer.put(EncryptData.MAGIC_NUMBER); // 504C4F4B
        byteBuffer.put(fileEncryptBytes);

        Files.write(filePath, byteBuffer.array(), StandardOpenOption.WRITE);
    }
}
