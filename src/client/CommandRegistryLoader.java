package client;

import common.CommandResponse;
import common.CommandType;
import java.util.Map;

public class CommandRegistryLoader {
    private final NetworkService network;

    public CommandRegistryLoader(NetworkService network) {
        this.network = network;
    }

    /**
     * Извлекает и валидирует карту команд из уже полученного ответа.
     * @param initResponse ответ сервера после рукопожатия
     * @return заполненный AllCommands или null при ошибке
     */
    public AllCommands loadCommands(CommandResponse initResponse) {
        if (initResponse == null) {
            System.err.println("Нет ответа от сервера");
            return null;
        }

        @SuppressWarnings("unchecked")
        Map<String, CommandType> commandsMap = (Map<String, CommandType>) initResponse.getData();

        if (commandsMap == null || commandsMap.isEmpty()) {
            System.err.println("Сервер не передал карту команд");
            network.disconnect();
            return null;
        }

        AllCommands allCommands = new AllCommands();
        allCommands.loadFromServer(commandsMap);
        return allCommands;
    }
}