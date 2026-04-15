package client;

public record ClientConfig(String host, int port) {

    // Значения по умолчанию
    public static ClientConfig defaultConfig() {
        return new ClientConfig("localhost", 7301);
    }
}