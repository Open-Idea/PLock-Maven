package net.openidea.plock;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;

public class EncryptData {

    public static final byte[] MAGIC_NUMBER = new byte[] {'P', 'L', 'O', 'C', 'K'};

    private static SecretKey generateAESKey() throws NoSuchAlgorithmException {
        final KeyGenerator keyGenerator;

        keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        return keyGenerator.generateKey();
    }

    private static byte[] encryptData(final byte[] bytes, final SecretKey secretKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        final Cipher cipher;

        if (bytes == null || secretKey == null)
            return null;
        cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(new byte[16]));
        return cipher.doFinal(bytes);
    }

    private static byte[] encryptAESKey(final SecretKey secretKey, final RSAPrivateKey rsaPrivateKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        final Cipher cipher;

        if (secretKey == null || rsaPrivateKey == null)
            return null;
        cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, rsaPrivateKey);
        return cipher.doFinal(secretKey.getEncoded());
    }

    public static byte[] encrypt(final byte[] bytes, final RSAPrivateKey rsaPrivateKey) throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
        final SecretKey aesKey = generateAESKey();
        final byte[] encryptedBytes = encryptData(bytes, aesKey);
        final byte[] encryptedAesKey = encryptAESKey(aesKey, rsaPrivateKey);
        final ByteBuffer byteBuffer;

        if (encryptedBytes == null || encryptedAesKey == null)
            return null;
        byteBuffer = ByteBuffer.allocate(4 + encryptedAesKey.length + encryptedBytes.length);
        byteBuffer.putInt(encryptedAesKey.length);
        byteBuffer.put(encryptedAesKey);
        byteBuffer.put(encryptedBytes);
        return byteBuffer.array();
    }

    public static void encryptFile(final Path filePath, final RSAPrivateKey rsaPrivateKey) throws IOException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
        final byte[] fileEncryptBytes;
        final ByteBuffer byteBuffer;

        if (filePath == null || rsaPrivateKey == null)
            return;
        fileEncryptBytes = encrypt(Files.readAllBytes(filePath), rsaPrivateKey);
        if (fileEncryptBytes == null)
            return;
        byteBuffer = ByteBuffer.allocate(EncryptData.MAGIC_NUMBER.length + fileEncryptBytes.length);
        byteBuffer.put(EncryptData.MAGIC_NUMBER); // 504C4F4B
        byteBuffer.put(fileEncryptBytes);

        Files.write(filePath, byteBuffer.array(), StandardOpenOption.WRITE);
    }
}
