package server.commands;


import server.collection.*;

import java.util.HashMap;
import java.util.Map;

public class CommandsList {

    VehicleCollection collection = new VehicleCollection();
    Invoker invoker = new Invoker();
    VehicleManager manager = new VehicleManager(collection);
    VehicleSaver saver = new VehicleSaver(collection);

    private final Map<String, Command> commandList = new HashMap<>();

    public CommandsList() {
        registratedCommand();
    }

    private void registratedCommand() {
        register("clear", new ClearCommand(manager));
        register("filter_greater_than_engine_power", new CompareByEnginePowerCommand(manager));
        register("info", new InfoCommand(manager));
        register("show", new ShowCommand(manager));
        register("remove_by_id", new RemoveByID(manager));
        register("print_descending", new PrintDescendingCommand(manager));
        register("save", new SaveCommand(saver));
        register("shuffle", new ShuffleCommand(manager));
        register("sort", new SortCommand(manager));
        register("filter_less_than_type", new FilterLessThatType(manager));
        register("add", new AddCommand(manager));
        register("add_if_max", new AddIfMax(manager));
        register("update", new UpdateElementID(manager));
        register("help", new HelpCommand(invoker.getCommands()));
        register("group_by", new GroupByCommand(manager));
    }

    private void register(String name, Command command) {
        commandList.put(name, command);
        invoker.registerCommand(name, command);
    }

    public Map<String, Command> getCommandList() {
        return commandList;
    }


    public Invoker getInvoker() {
        return invoker;
    }
}