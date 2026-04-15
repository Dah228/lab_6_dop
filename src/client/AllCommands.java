package client;

import common.CommandType;
import java.util.HashMap;
import java.util.Map;

public class AllCommands {
    private final Map<String, CommandType> commandsInfo;

    // Конструктор без параметров
    public AllCommands() {
        this.commandsInfo = new HashMap<>();
    }

    // Метод для загрузки команд с сервера
    public void loadFromServer(Map<String, CommandType> commandsMap) {
        if (commandsMap != null) {
            this.commandsInfo.putAll(commandsMap);
        }
    }

    public CommandType getCommandType(String commandName) {
        return commandsInfo.get(commandName);
    }

    public boolean hasCommand(String commandName) {
        return commandsInfo.containsKey(commandName);
    }

}