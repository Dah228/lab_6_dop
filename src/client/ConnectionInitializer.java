package client;

import common.CommandResponse;
import common.*;
import java.security.*;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;

public class ConnectionInitializer {
    private final NetworkService network;
    private final String expectedHandshake;

    public ConnectionInitializer(NetworkService network, String expectedHandshake) {
        this.network = network;
        this.expectedHandshake = expectedHandshake;
    }

    public CommandResponse initialize() {
        if (!network.connect()) return null;

        try {
            // 1. Клиент отправляет challenge
            var ch = HandshakeMessages.ClientHello.generate();
            network.sendRaw(ch);

            // 2. Ждём ServerHello
            Object resp = network.receiveRaw();
            if (!(resp instanceof HandshakeMessages.ServerHello sh)) {
                System.err.println("Неверный ответ сервера при рукопожатии");
                network.disconnect();
                return null;
            }

            // 3. Клиент проверяет подпись
            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initVerify(KeyLoader.loadPublic("keys/server/server.public.pem"));            sig.update(java.util.Base64.getDecoder().decode(ch.challenge()));
            if (!sig.verify(java.util.Base64.getDecoder().decode(sh.challengeSignature()))) {
                System.err.println("Подпись сервера невалидна!");
                network.disconnect();
                return null;
            }

            // 4. Клиент генерирует AES ключ и шифрует его публичным ключом сервера
            KeyGenerator aesGen = KeyGenerator.getInstance("AES");
            aesGen.init(256);
            byte[] sessionKey = aesGen.generateKey().getEncoded();

            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, KeyLoader.loadPublic("keys/server/server.public.pem"));            byte[] encKey = cipher.doFinal(sessionKey);

            // 5. Отправляем зашифрованный ключ
            network.sendRaw(new HandshakeMessages.SessionKeyExchange(java.util.Base64.getEncoder().encodeToString(encKey)));

            // Сохраняем ключ в NetworkService для дальнейшего AES-шифрования
            network.setSessionKey(sessionKey);

            // 6. Получаем финальный CommandResponse (connected + карта команд)
            CommandResponse initResponse = network.receive();
            if (initResponse == null || !expectedHandshake.equals(initResponse.getMessage())) {
                System.err.println("Ошибка инициализации: неверный ответ сервера");
                network.disconnect();
                return null;
            }
            return initResponse;

        } catch (Exception e) {
            System.err.println("Ошибка рукопожатия: " + e.getMessage());
            //noinspection CallToPrintStackTrace
            e.printStackTrace();
            network.disconnect();
            return null;
        }
    }
}