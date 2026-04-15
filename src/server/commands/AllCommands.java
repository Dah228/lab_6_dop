package server.commands;

import common.CommandType;

import java.util.HashMap;
import java.util.Map;


public class AllCommands {

    private final Map<String, CommandType> commandsInfo;

    public AllCommands(CommandsList commandsList) {
        this.commandsInfo = new HashMap<>();
        initializeCommandsFromList(commandsList);
    }

    private void initializeCommandsFromList(CommandsList commandsList) {
        Map<String, Command> allCommands = commandsList.getCommandList();

        for (Map.Entry<String, Command> entry : allCommands.entrySet()) {
            String commandName = entry.getKey();
            if (commandName.equals("execute_script")) {
                commandsInfo.put(commandName, CommandType.WITHARGS);
                continue;
            }
            Command command = entry.getValue();
            CommandType type = command.getType();
            commandsInfo.put(commandName, type);
        }
    }

    public CommandType getCommandType(String commandName) {
        return commandsInfo.get(commandName);
    }

    public Map<String, CommandType> getAll() {
        return commandsInfo;
    }
}