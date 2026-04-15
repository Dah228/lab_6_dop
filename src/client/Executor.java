package client;

import common.CommandRequest;
import common.CommandResponse;
import common.CommandType;
import common.Vehicle;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.util.List;

public class Executor {
    private final NetworkService network;
    private final AllCommands allCommands;
    private final DataValidator validator;

    public Executor(NetworkService network, AllCommands allCommands, DataValidator validator) {
        this.network = network;
        this.allCommands = allCommands;
        this.validator = validator;
    }

    public void run(InputStream inputStream) {
        // Переключаем валидатор на текущий поток
        validator.setInputStream(inputStream);

        // Создаём BufferedReader для чтения команд
        BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
        boolean isInteractive = !(inputStream instanceof FileInputStream);

        if (isInteractive) {
            System.out.println("Подключено. Введите команду или 'help' для списка.");
        }

        try {
            while (network.isConnected()) {
                if (isInteractive) {
                    System.out.print("> ");
                }

                String input = reader.readLine();
                if (input == null) break; // конец файла

                input = input.trim();
                if (input.isEmpty()) continue;
                if (input.equals("exit")) break;

                String[] tokens = input.split("\\s+");
                String commandName = tokens[0];
                List<String> args = Arrays.asList(tokens);

                // === EXECUTE_SCRIPT ===
                if (commandName.equals("execute_script")) {
                    if (args.size() < 2) {
                        System.out.println("Ошибка: укажите имя файла скрипта");
                        continue;
                    }
                    String filename = args.get(1);
                    File scriptFile = new File(filename);

                    if (!scriptFile.exists()) {
                        System.out.println("Ошибка: файл '" + filename + "' не найден");
                        continue;
                    }

                    try (FileInputStream fileStream = new FileInputStream(scriptFile)) {
                        if (isInteractive) System.out.println("Выполнение скрипта: " + filename);
                        run(fileStream); // рекурсивный вызов
                        if (isInteractive) System.out.println("Скрипт завершён");
                    } catch (Exception e) {
                        System.out.println("Ошибка выполнения скрипта: " + e.getMessage());
                    }
                    continue;
                }

                if (!allCommands.hasCommand(commandName)) {
                    if (isInteractive) {
                        System.out.println("Неизвестная команда: " + commandName);
                    }
                    continue;
                }

                CommandType type = allCommands.getCommandType(commandName);
                if (type == null) continue;

                Vehicle vehicle = null;
                // Если команда требует ввода модели (аргументы читаются из потока)
                if (type == CommandType.WITHMODEL || type == CommandType.WITHARGSMODEL) {
                    if (isInteractive) {
                        System.out.println("Введите данные транспортного средства:");
                    }
                    try {
                        // isInteractive здесь выступает как флаг "нужно ли выводить подсказки"
                        // В DataValidator он называется isLaud
                        vehicle = validator.parseVehicle(isInteractive);
                    } catch (Exception e) {
                        if (isInteractive) {
                            System.out.println("Ошибка ввода данных: " + e.getMessage());
                        }
                        continue;
                    }
                }

                CommandRequest request = new CommandRequest(commandName, args, vehicle, isInteractive);

                if (!network.send(request)) {
                    System.out.println("Ошибка отправки запроса");
                    break;
                }

                CommandResponse response = network.receive();
                if (response == null) {
                    System.out.println("Нет ответа от сервера (соединение разорвано)");
                    break;
                }

                handleResponse(response);
            }
        } catch (Exception e) {
            if (isInteractive) {
                System.err.println("Критическая ошибка: " + e.getMessage());
                e.printStackTrace();
            }
        }

        if (isInteractive) {
            System.out.println("Завершение работы...");
        }
    }

    private void handleResponse(CommandResponse response) {
        if (response.isSuccess()) {
            if (response.getMessage() != null && !response.getMessage().isEmpty()) {
                System.out.println(response.getMessage());
            }
        } else {
            System.out.println("Ошибка сервера: " + response.getMessage());
        }
    }
}