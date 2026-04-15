package client;

import common.CommandResponse;

public class ConnectionInitializer {
    private final NetworkService network;
    private final String expectedHandshake;

    public ConnectionInitializer(NetworkService network, String expectedHandshake) {
        this.network = network;
        this.expectedHandshake = expectedHandshake;
    }

    /**
     * Подключается и проверяет рукопожатие.
     * @return CommandResponse с данными (картой команд) или null при ошибке
     */
    public CommandResponse initialize() {
        if (!network.connect()) {
            System.err.println("Не удалось подключиться к серверу");
            return null;
        }

        CommandResponse initResponse = network.receive();
        if (initResponse == null || !expectedHandshake.equals(initResponse.getMessage())) {
            System.err.println("Ошибка инициализации: неверный ответ сервера");
            network.disconnect();
            return null;
        }
        return initResponse; // ← возвращаем тот же ответ, в котором лежат команды
    }
}