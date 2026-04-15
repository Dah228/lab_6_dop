package server;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;

public class KeyGenerator {

    public static void main(String[] args) throws Exception {
        System.out.println("Генерация ключей сервера...");
        generateAndSave("server", "server");

        System.out.println("\nГенерация ключей клиента...");
        generateAndSave("client", "client");

        System.out.println("\nКлючи сохранены:");
        System.out.println("   Сервер: keys/server/");
        System.out.println("   Клиент: keys/client/");
    }

    private static void generateAndSave(String entity, String subfolder) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair keyPair = kpg.generateKeyPair();

        String privatePem = toPem("PRIVATE KEY", keyPair.getPrivate().getEncoded());
        String publicPem = toPem("PUBLIC KEY", keyPair.getPublic().getEncoded());

        // Создаем подпапку для каждого участника
        java.nio.file.Path dir = Paths.get("keys", subfolder);
        Files.createDirectories(dir);

        Files.writeString(dir.resolve(entity + ".private.pem"), privatePem);
        Files.writeString(dir.resolve(entity + ".public.pem"), publicPem);

        System.out.println("Сгенерировано: " + entity + " → keys/" + subfolder + "/");
    }

    private static String toPem(String type, byte[] encoded) {
        String base64 = Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(encoded);
        return "-----BEGIN " + type + "-----\n" + base64 + "\n-----END " + type + "-----\n";
    }
}