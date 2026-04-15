package server.service;

import common.CommandType;
import common.ReturnCode;
import server.commands.Command;
import server.commands.Invoker;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

public class ConsoleCommandHandler implements Runnable {

    private final Invoker invoker;
    private final ServerContext context;
    private volatile boolean running = true;

    public ConsoleCommandHandler(Invoker invoker, ServerContext context) {
        this.invoker = invoker;
        this.context = context;
    }

    public void stop() {
        running = false;
    }

    @Override
    public void run() {
        BufferedReader consoleReader = new BufferedReader(new InputStreamReader(System.in));
        try {
            String line;
            while (running && (line = consoleReader.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty()) continue;

                if (line.equals("exit")) {
                    System.out.println("Остановка сервера...");
                    context.stop();
                    break;
                }

                if (invoker.getCommands().get(line).getType().equals(CommandType.NOARGS)) {
                    executeConsoleCommand(line);
                }
                else{
                    continue;
                }
            }
        } catch (Exception e) {
            System.err.println("Ошибка чтения консоли: " + e.getMessage());
        }
    }

    private void executeConsoleCommand(String line) {
        String[] tokens = line.split("\\s+");
        String commandName = tokens[0];
        List<String> arguments = Arrays.asList(tokens);

        System.out.printf("Консоль: %s | args=%s%n", commandName, arguments);

        NetworkResponseSender consoleSender = new NetworkResponseSender();

        ReturnCode statusCode = invoker.executeCommand(
                commandName,
                arguments,
                null,
                true,
                consoleSender
        );

        String output = consoleSender.getOutput();
        if (!output.isEmpty()) {
            System.out.println(output);
        } else {
            System.out.println(statusCode == ReturnCode.OK ? "Команда выполнена" : "Ошибка выполнения");
        }
    }
}