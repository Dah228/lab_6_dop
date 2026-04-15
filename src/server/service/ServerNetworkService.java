package server.service;

import common.*;
import server.commands.Command;
import server.commands.CommandsList;

import javax.crypto.Cipher;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.*;
import java.security.PublicKey;
import java.security.Signature;
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


        public SecureSerializer secureSerializer;


        public enum HandshakeState { WAITING_CHALLENGE, WAITING_KEY_EXCHANGE, COMPLETED }
        public HandshakeState hsState = HandshakeState.WAITING_CHALLENGE;
        public byte[] pendingChallenge = null;
        public byte[] sessionKey = null; // сюда сохраним AES ключ после обмена

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
    public void queueResponse(SocketChannel clientChannel, Object response) {
        try {
            ClientData client = clients.get(clientChannel);
            byte[] data;

            // СНАЧАЛА определяем, нужно ли шифровать
            if (client != null && client.secureSerializer != null) {
                data = client.secureSerializer.encryptAndSerialize(response);
            } else {
                data = Serializer.serialize(response);
            }

            // ТЕПЕРЬ создаём буфер с ПРАВИЛЬНЫМИ данными
            ByteBuffer sizeBuffer = ByteBuffer.allocate(4);
            sizeBuffer.putInt(data.length);
            sizeBuffer.flip();

            ByteBuffer message = ByteBuffer.allocate(4 + data.length);
            message.put(sizeBuffer);
            message.put(data);
            message.flip();

            if (client != null) {
                synchronized (client.writeQueue) {
                    client.writeQueue.offer(message);
                }
                clientChannel.register(selector, SelectionKey.OP_READ | SelectionKey.OP_WRITE);
            }
        } catch (Exception e) {
            System.out.println("Ошибка подготовки ответа: " + e.getMessage());
            e.printStackTrace();
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
//            sendCommandsMap(clientChannel);
            System.out.println("Ожидание handshake от " + clientChannel.getRemoteAddress());

        }
    }


    private void sendCommandsMap(SocketChannel clientChannel) {
        try {
            Map<String, CommandType> commandsMap = new HashMap<>();
            Map<String, Command> allCommands = commandsList.getCommandList();
            for (Map.Entry<String, Command> entry : allCommands.entrySet()) {
                String commandName = entry.getKey();
                Command command = entry.getValue();
                commandsMap.put(commandName, command.getType());
            }

            CommandResponse initResponse = new CommandResponse(
                    true,
                    "connected",
                    commandsMap
            );

            queueResponse(clientChannel, initResponse);

            System.out.println("📤 Карта команд отправлена для " + clientChannel.getRemoteAddress());
        } catch (Exception e) {
            System.out.println("Ошибка отправки карты команд: " + e.getMessage());
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

            Object obj;
            if (data.secureSerializer != null) {
                obj = data.secureSerializer.decryptAndDeserialize(bytes);
            } else {
                obj = Serializer.deserialize(bytes);
            }
            return (CommandRequest) obj;

        } catch (IOException | ClassNotFoundException e) {
            System.out.println("Ошибка чтения от клиента: " + e.getMessage());
            removeClient(clientChannel);
            return null;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private void handleRead(SelectionKey key) {
        SocketChannel clientChannel = (SocketChannel) key.channel();
        ClientData data = clients.get(clientChannel);
        if (data == null) return;

        try {
            // Если рукопожатие ещё не завершено — обрабатываем его отдельно
            if (data.hsState != ClientData.HandshakeState.COMPLETED) {
                processHandshake(clientChannel, data);
                return;
            }

            // Обычная логика: читаем CommandRequest
            CommandRequest request = readFromClient(clientChannel);
            if (request != null) {
                key.attach(request);
            }
        } catch (Exception e) {
            System.out.println("Ошибка чтения: " + e.getMessage());
            removeClient(clientChannel);
        }
    }



    private void processHandshake(SocketChannel clientChannel, ClientData data) throws Exception {
        Object msg = Serializer.deserialize(readRawMessage(clientChannel));

        if (data.hsState == ClientData.HandshakeState.WAITING_CHALLENGE && msg instanceof HandshakeMessages.ClientHello ch) {
            data.pendingChallenge = java.util.Base64.getDecoder().decode(ch.challenge());

            // Подписываем challenge серверным приватным ключом
            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initSign(KeyLoader.loadPrivate("keys/server/server.private.pem"));
            sig.update(data.pendingChallenge);
            String sigB64 = java.util.Base64.getEncoder().encodeToString(sig.sign());

            // Формируем сертификат
            PublicKey serverPub = KeyLoader.loadPublic("keys/server/server.public.pem");
            String pubB64 = java.util.Base64.getEncoder().encodeToString(serverPub.getEncoded());
            var cert = new HandshakeMessages.ServerCertificate(
                    pubB64, "main-server", "2024-01-01", "2025-01-01", sigB64
            );

            queueResponse(clientChannel, new HandshakeMessages.ServerHello(cert, sigB64));
            data.hsState = ClientData.HandshakeState.WAITING_KEY_EXCHANGE;

        } else if (data.hsState == ClientData.HandshakeState.WAITING_KEY_EXCHANGE && msg instanceof HandshakeMessages.SessionKeyExchange sk) {
            byte[] encryptedKey = java.util.Base64.getDecoder().decode(sk.encryptedKey());

            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            cipher.init(Cipher.DECRYPT_MODE, KeyLoader.loadPrivate("keys/server/server.private.pem"));
            data.sessionKey = cipher.doFinal(encryptedKey);

            data.secureSerializer = new SecureSerializer(data.sessionKey);

            data.hsState = ClientData.HandshakeState.COMPLETED;
            System.out.println("Рукопожатие завершено для " + clientChannel.getRemoteAddress());
            sendCommandsMap(clientChannel);
        } else {
            removeClient(clientChannel); // Неизвестное состояние
        }
    }


    // Вспомогательный: читает сырые байты (4 байта размер + payload)
    private byte[] readRawMessage(SocketChannel ch) throws Exception {
        java.nio.ByteBuffer sizeBuf = java.nio.ByteBuffer.allocate(4);
        while (sizeBuf.hasRemaining()) ch.read(sizeBuf);
        sizeBuf.flip();
        int len = sizeBuf.getInt();
        java.nio.ByteBuffer dataBuf = java.nio.ByteBuffer.allocate(len);
        while (dataBuf.hasRemaining()) ch.read(dataBuf);
        return dataBuf.array();
    }

    public boolean sendTo(SocketChannel clientChannel, CommandResponse response) {
        if (clientChannel == null || !clientChannel.isOpen()) {
            return false;
        }
        try {
            ClientData client = clients.get(clientChannel);
            byte[] data;

            if (client != null && client.secureSerializer != null) {
                data = client.secureSerializer.encryptAndSerialize(response);
            } else {
                data = Serializer.serialize(response);
            }

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
        } catch (Exception e) {
            throw new RuntimeException(e);
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