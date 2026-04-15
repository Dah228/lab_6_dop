package server.service;

import common.CommandRequest;
import common.CommandResponse;
import common.CommandType;
import common.Serializer;
import server.commands.Command;
import server.commands.CommandsList;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class ServerNetworkService {
    private ServerSocketChannel serverChannel;
    private final Selector selector;
    private final int port;
    private final CommandsList commandsList;

    private final Map<SocketChannel, ClientData> clients = new ConcurrentHashMap<>();

    public static class ClientData {
        public ByteBuffer sizeBuffer = ByteBuffer.allocate(4);
        public ByteBuffer dataBuffer;
        public int expectedSize = -1;
        public boolean readingSize = true;
        public boolean initialized = false;
        private final int maxpack = 1000;
        public final Queue<ByteBuffer> writeQueue = new ArrayDeque<>();
        public ByteBuffer currentWriteBuffer = null;

        public void reset() {
            sizeBuffer.clear();
            dataBuffer = null;
            expectedSize = -1;
            readingSize = true;
        }
    }

    public ServerNetworkService(int port, CommandsList commandsList) {
        this.port = port;
        this.commandsList = commandsList;
        try {
            selector = Selector.open();
        } catch (IOException e) {
            throw new RuntimeException("Не удалось создать селектор", e);
        }
    }
    // Метод отправки — только ставим в очередь, не пишем сразу
    public void queueResponse(SocketChannel clientChannel, CommandResponse response) {
        try {
            byte[] data = Serializer.serialize(response);
            ByteBuffer sizeBuffer = ByteBuffer.allocate(4);
            sizeBuffer.putInt(data.length);
            sizeBuffer.flip();

            // Объединяем размер + данные в один буфер
            ByteBuffer message = ByteBuffer.allocate(4 + data.length);
            message.put(sizeBuffer);
            message.put(data);
            message.flip();

            ClientData client = clients.get(clientChannel);
            if (client != null) {
                synchronized (client.writeQueue) {
                    client.writeQueue.offer(message);
                }
                // Регистрируем интерес к записи, если очередь была пуста
                clientChannel.register(selector, SelectionKey.OP_READ | SelectionKey.OP_WRITE);
            }
        } catch (IOException e) {
            removeClient(clientChannel);
        }
    }

    public boolean start() {
        try {
            serverChannel = ServerSocketChannel.open();
            serverChannel.configureBlocking(false);
            serverChannel.bind(new InetSocketAddress(port));
            serverChannel.register(selector, SelectionKey.OP_ACCEPT);
            System.out.println("Сервер запущен на порту " + port + ", ожидание подключений...");
            return true;
        } catch (IOException e) {
            System.out.println("Не удалось запустить сервер: " + e.getMessage());
            return false;
        }
    }

    public List<SelectionKey> processEvents() {
        try {
            // Блокируемся до появления хотя бы одного события
            selector.select();

            Iterator<SelectionKey> keys = selector.selectedKeys().iterator();
            List<SelectionKey> readyKeys = new ArrayList<>();

            while (keys.hasNext()) {
                SelectionKey key = keys.next();
                keys.remove();

                if (!key.isValid()) continue;

                if (key.isAcceptable()) {
                    handleAccept(key);
                } else if (key.isReadable()) {
                    handleRead(key);
                } else if (key.isWritable()) {
                    handleWrite(key); // ← новая логика для асинхронной отправки
                }

                if (key.attachment() instanceof CommandRequest) {
                    readyKeys.add(key);
                }
            }
            return readyKeys;
        } catch (IOException e) {
            System.out.println("Ошибка обработки событий: " + e.getMessage());
            return Collections.emptyList();
        }
    }

    // Обработчик события записи
    private void handleWrite(SelectionKey key) throws IOException {
        SocketChannel clientChannel = (SocketChannel) key.channel();
        ClientData client = clients.get(clientChannel);
        if (client == null) {
            key.cancel();
            return;
        }

        synchronized (client.writeQueue) {
            // Если нет текущего буфера, берём следующий из очереди
            if (client.currentWriteBuffer == null) {
                client.currentWriteBuffer = client.writeQueue.poll();
            }

            // Пишем, пока буфер не исчерпан или сокет не заблокируется
            while (client.currentWriteBuffer != null && client.currentWriteBuffer.hasRemaining()) {
                if (clientChannel.write(client.currentWriteBuffer) == -1) {
                    removeClient(clientChannel);
                    return;
                }
            }

            // Если дописали — сбрасываем и проверяем очередь
            if (client.currentWriteBuffer != null && !client.currentWriteBuffer.hasRemaining()) {
                client.currentWriteBuffer = null;
            }

            // Если очередь пуста — отменяем интерес к записи
            if (client.writeQueue.isEmpty() && client.currentWriteBuffer == null) {
                key.interestOps(SelectionKey.OP_READ);
            }
        }
    }


    private void handleAccept(SelectionKey key) throws IOException {
        ServerSocketChannel serverChannel = (ServerSocketChannel) key.channel();
        SocketChannel clientChannel = serverChannel.accept();

        if (clientChannel != null) {
            clientChannel.configureBlocking(false);
            // Регистрируем только на чтение — запись по необходимости
            clientChannel.register(selector, SelectionKey.OP_READ);
            clients.put(clientChannel, new ClientData());

            System.out.println("Клиент подключён: " + clientChannel.getRemoteAddress());

            // Отправляем карту команд через очередь
            sendCommandsMap(clientChannel);
        }
    }


    private void sendCommandsMap(SocketChannel clientChannel) {
        try {
            // 1. Формируем карту команд
            Map<String, CommandType> commandsMap = new HashMap<>();
            Map<String, Command> allCommands = commandsList.getCommandList();

            for (Map.Entry<String, Command> entry : allCommands.entrySet()) {
                String commandName = entry.getKey();
                Command command = entry.getValue();
                commandsMap.put(commandName, command.getType());
            }

            // 2. Создаём ответ
            CommandResponse initResponse = new CommandResponse(
                    true,
                    "connected",
                    commandsMap
            );

            // 3. Ставим в очередь отправки (не блокируем поток!)
            queueResponse(clientChannel, initResponse);

            // 4. Помечаем клиента как инициализированного
            //    (протокольно: мы "отправили", фактическая доставка — дело селектора)
            ClientData data = clients.get(clientChannel);
            if (data != null) {
                data.initialized = true;
            }

            System.out.println("Карта команд поставлена в очередь для " +
                    clientChannel.getRemoteAddress());

        } catch (IOException e) {
            System.out.println("Ошибка подготовки карты команд: " + e.getMessage());
            removeClient(clientChannel);
        }
    }

    public CommandRequest readFromClient(SocketChannel clientChannel) {
        ClientData data = clients.get(clientChannel);
        if (data == null) return null;

        try {
            if (data.readingSize) {
                while (data.sizeBuffer.hasRemaining()) {
                    if (clientChannel.read(data.sizeBuffer) == -1) {
                        removeClient(clientChannel);
                        return null;
                    }
                }

                data.sizeBuffer.flip();
                data.expectedSize = data.sizeBuffer.getInt();
                data.sizeBuffer.clear();

                if (data.expectedSize <= 0 || data.expectedSize > data.maxpack) {
                    System.out.println("Некорректный размер сообщения: " + data.expectedSize);
                    removeClient(clientChannel);
                    return null;
                }

                data.dataBuffer = ByteBuffer.allocate(data.expectedSize);
                data.readingSize = false;
            }

            while (data.dataBuffer.hasRemaining()) {
                if (clientChannel.read(data.dataBuffer) == -1) {
                    removeClient(clientChannel);
                    return null;
                }
            }

            data.dataBuffer.flip();
            byte[] bytes = new byte[data.expectedSize];
            data.dataBuffer.get(bytes);

            data.reset();

            return (CommandRequest) Serializer.deserialize(bytes);

        } catch (IOException | ClassNotFoundException e) {
            System.out.println("Ошибка чтения от клиента: " + e.getMessage());
            removeClient(clientChannel);
            return null;
        }
    }

    private void handleRead(SelectionKey key) {
        SocketChannel clientChannel = (SocketChannel) key.channel();
        CommandRequest request = readFromClient(clientChannel);

        if (request != null) {
            key.attach(request);
        }
    }

    public boolean sendTo(SocketChannel clientChannel, CommandResponse response) {
        if (clientChannel == null || !clientChannel.isOpen()) {
            return false;
        }

        try {
            byte[] data = Serializer.serialize(response);
            ByteBuffer buffer = ByteBuffer.wrap(data);

            ByteBuffer sizeBuffer = ByteBuffer.allocate(4);
            sizeBuffer.putInt(data.length);
            sizeBuffer.flip();

            while (sizeBuffer.hasRemaining()) {
                clientChannel.write(sizeBuffer);
            }

            while (buffer.hasRemaining()) {
                clientChannel.write(buffer);
            }

            return true;
        } catch (IOException e) {
            System.out.println("Ошибка отправки ответа: " + e.getMessage());
            removeClient(clientChannel);
            return false;
        }
    }


    public void removeClient(SocketChannel clientChannel) {
        if (clientChannel != null) {
            clients.remove(clientChannel);
            try {
                clientChannel.close();
            } catch (IOException ignored) {}
            System.out.println("Клиент отключён (осталось: " + clients.size() + ")");
        }
    }

    public void stop() {
        for (SocketChannel client : clients.keySet()) {
            try {
                client.close();
            } catch (IOException ignored) {}
        }
        clients.clear();

        try {
            if (serverChannel != null && serverChannel.isOpen()) {
                serverChannel.close();
            }
            if (selector != null && selector.isOpen()) {
                selector.close();
            }
            System.out.println("Сервер остановлен");
        } catch (IOException e) {
            System.out.println("Ошибка при остановке сервера: " + e.getMessage());
        }
    }
}