package server.commands;

import common.ReturnCode;
import common.Vehicle;
import server.service.NetworkResponseSender;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Invoker {
    private final Map<String, Command> commands = new HashMap<>();

    public void registerCommand(String commandName, Command command) {
        commands.put(commandName, command);
    }

    // Создаём CommandParams внутри и передаём команде
    public ReturnCode executeCommand(
            String commandName,
            List<String> args,
            Vehicle vehicle,
            Boolean isLaud,
            NetworkResponseSender responseSender
    ) {
        Command command = commands.get(commandName);

        // 1. Команда не найдена
        if (command == null) {
            if (isLaud) {
                responseSender.sendError("Неизвестная команда: " + commandName);
            }
            return ReturnCode.FAILED;
        }

        try {
            CommandParams params = new CommandParams(args, vehicle, isLaud, responseSender);
            ReturnCode result = command.execute(params);  //Команда только возвращает код

            // 2. Автоматическая обработка результата
            if (result == ReturnCode.FAILED && isLaud) {
                responseSender.sendError("Команда '" + commandName + "' завершилась с ошибкой");
            }

            return result;

        } catch (IllegalArgumentException e) {
            // Ошибка валидации аргументов — всегда сообщаем клиенту
            if (isLaud) {
                responseSender.sendError("Неверные аргументы: " + e.getMessage());
            }
            return ReturnCode.FAILED;

        } catch (Exception e) {
            // Неожиданная ошибка — логируем на сервере, клиенту — общее сообщение
            System.out.println("Ошибка выполнения " + commandName + ": " + e.getMessage());
            if (isLaud) {
                responseSender.sendError("Внутренняя ошибка сервера при выполнении команды");
            }
            return ReturnCode.FAILED;
        }
    }

    public Map<String, Command> getCommands() {
        return commands;
    }
}