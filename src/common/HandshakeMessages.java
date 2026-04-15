package common;


import java.io.Serializable;
import java.security.SecureRandom;
import java.util.Base64;

public class HandshakeMessages {
    public record ClientHello(String challenge) implements Serializable {
        public static ClientHello generate() {
            byte[] bytes = new byte[32];
            new SecureRandom().nextBytes(bytes);
            return new ClientHello(Base64.getEncoder().encodeToString(bytes));
        }
    }

    public record ServerCertificate(String publicKey, String owner, String validFrom, String validTo, String signature) implements Serializable {}

    public record ServerHello(ServerCertificate certificate, String challengeSignature) implements Serializable {}

    public record SessionKeyExchange(String encryptedKey) implements Serializable {}
}