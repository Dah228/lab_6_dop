package client;

import common.CommandResponse;

public class Main {
    private static final String HANDSHAKE_EXPECTED = "connected";

    public static void main(String[] args) {
        // 1. Конфигурация
        ClientConfig config = ClientConfig.defaultConfig();

        // 2. Подключение + рукопожатие
        NetworkService network = new NetworkService(config.host(), config.port());
        ConnectionInitializer initializer = new ConnectionInitializer(network, HANDSHAKE_EXPECTED);
        CommandResponse initResponse = initializer.initialize();
        if (initResponse == null) {
            return; // ошибка уже выведена
        }

        // 3. Загрузка команд из того же ответа
        CommandRegistryLoader registryLoader = new CommandRegistryLoader(network);
        AllCommands allCommands = registryLoader.loadCommands(initResponse);
        if (allCommands == null) {
            return; // ошибка уже выведена
        }

        // 4. Бизнес-логика
        DataValidator validator = new DataValidator(System.in, true);
        Executor executor = new Executor(network, allCommands, validator);

        // 5. Запуск
        System.out.println("Клиент готов. Введите команду (или 'help'):");
        executor.run(System.in);

        // 6. Завершение
        network.disconnect();
        System.out.println("Клиент завершил работу");
    }
}