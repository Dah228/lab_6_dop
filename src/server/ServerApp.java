package server;

import server.service.*;

public class ServerApp {
    public static void main(String[] args) {
        System.out.println("Инициализация сервера...");

        if (args.length < 1) {
            System.err.println("Не указан путь к XML-файлу");
            return;
        }

        // 1. Создание контекста со всеми компонентами
        ServerContext context = new ServerContext(7301, args[0]);

        if (!context.startNetwork()) {
            System.err.println("Не удалось запустить сервер");
            return;
        }

        System.out.println("Сервер запущен. Команды: " +
                context.getCommandsList().getCommandList().size());
        System.out.println("Введите команду в консоль сервера или 'help' для списка.");

        // 2. Загрузка данных из XML
        XmlDataLoader.loadAndRegister(context.getXmlFilePath(), context.getInvoker());

        // 3. Подготовка обработчиков
        NetworkRequestHandler requestHandler = new NetworkRequestHandler(
                context.getInvoker(),
                context.getNetworkService()
        );
        ConsoleCommandHandler consoleHandler = new ConsoleCommandHandler(
                context.getInvoker(),
                context
        );
        ServerLoop serverLoop = new ServerLoop(context, requestHandler);

        // 4. Запуск потока консоли
        Thread consoleThread = new Thread(consoleHandler);
        consoleThread.setDaemon(true);
        consoleThread.start();

        // 5. Запуск главного цикла (в текущем потоке)
        serverLoop.run();
    }
}