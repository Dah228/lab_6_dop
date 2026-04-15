package common;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Обёртка над Serializer: шифрует/расшифровывает данные через AES-256-GCM.
 * Формат пакета: [4 байта: общая длина][12 байт: IV][ciphertext+auth_tag]
 */
public class SecureSerializer {
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int IV_LENGTH = 12;      // 96 бит — рекомендуется для GCM
    private static final int TAG_LENGTH_BIT = 128; // 16 байт — размер тега аутентификации

    private final byte[] sessionKey; // AES-256 ключ (32 байта)

    public SecureSerializer(byte[] sessionKey) {
        if (sessionKey == null || sessionKey.length != 32) {
            throw new IllegalArgumentException("Требуется 256-битный ключ (32 байта)");
        }
        this.sessionKey = sessionKey;
    }

    /**
     * Шифрует объект: сериализует → AES-GCM → возвращает байты для отправки по сети.
     */
    public byte[] encryptAndSerialize(Object obj) throws Exception {
        // 1. Сериализуем объект в байты (используем твой существующий Serializer)
        byte[] plaintext = common.Serializer.serialize(obj);

        // 2. Генерируем уникальный IV для этого пакета
        byte[] iv = new byte[IV_LENGTH];
        new SecureRandom().nextBytes(iv);

        // 3. Шифруем через AES-GCM
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        GCMParameterSpec spec = new GCMParameterSpec(TAG_LENGTH_BIT, iv);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(sessionKey, "AES"), spec);

        byte[] ciphertext = cipher.doFinal(plaintext); // ciphertext + auth tag

        // 4. Упаковываем: [IV][ciphertext+tag]
        byte[] result = new byte[IV_LENGTH + ciphertext.length];
        System.arraycopy(iv, 0, result, 0, IV_LENGTH);
        System.arraycopy(ciphertext, 0, result, IV_LENGTH, ciphertext.length);

        return result;
    }

    /**
     * Принимает зашифрованные байты → расшифровывает → десериализует в объект.
     */
    public Object decryptAndDeserialize(byte[] encrypted) throws Exception {
        // 1. Извлекаем IV (первые 12 байт)
        byte[] iv = Arrays.copyOfRange(encrypted, 0, IV_LENGTH);
        byte[] ciphertext = Arrays.copyOfRange(encrypted, IV_LENGTH, encrypted.length);

        // 2. Расшифровываем
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        GCMParameterSpec spec = new GCMParameterSpec(TAG_LENGTH_BIT, iv);
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(sessionKey, "AES"), spec);

        byte[] plaintext = cipher.doFinal(ciphertext); // выбросит ошибку, если тег не совпадает

        // 3. Десериализуем обратно в объект
        return common.Serializer.deserialize(plaintext);
    }
}