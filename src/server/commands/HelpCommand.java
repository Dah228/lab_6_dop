package server.commands;

import common.CommandType;
import common.ReturnCode;

import java.util.Map;


public class HelpCommand implements Command {
    private final Map<String, Command> allCommands;
    private final CommandType type = CommandType.NOARGS;


    public HelpCommand(Map<String, Command> allCommands){
        this.allCommands = allCommands;
    }

    @Override
    public ReturnCode execute(CommandParams params) {
        if (params.args().size() != 1) return ReturnCode.FAILED;
        params.responseSender().send("=== Доступные команды ===");
        for (Map.Entry<String, Command> entry : allCommands.entrySet()) {
            String name = entry.getKey();
            String description = entry.getValue().getDescription();
            params.responseSender().send(name + " - " + description);
        }
        params.responseSender().send("=========================");
        return ReturnCode.OK;
    }

    @Override
    public String  getDescription(){
        return "вывести справку по доступным командам";
    }


    @Override
    public CommandType getType() {
        return this.type;
    }

}
