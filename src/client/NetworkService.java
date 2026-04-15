package client;

import common.CommandRequest;
import common.CommandResponse;
import common.SecureSerializer;
import common.Serializer;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;

public class NetworkService {
    private SocketChannel channel;
    private final String host;
    private final int port;

    public NetworkService(String host, int port) {
        this.host = host;
        this.port = port;
    }

    private SecureSerializer secureSerializer; // null до завершения рукопожатия



    public boolean connect() {
        try {
            channel = SocketChannel.open();
            channel.configureBlocking(true); // Блокирующий режим
            channel.connect(new InetSocketAddress(host, port));

            System.out.println("Подключено к серверу " + host + ":" + port);
            return true;
        } catch (IOException e) {
            System.out.println("Не удалось подключиться к серверу: " + e.getMessage());
            return false;
        }
    }

    public void sendRaw(Object obj) throws Exception {
        byte[] data = Serializer.serialize(obj);
        ByteBuffer sizeBuf = ByteBuffer.allocate(4).putInt(data.length);
        sizeBuf.flip();
        channel.write(sizeBuf);
        channel.write(ByteBuffer.wrap(data));
    }

    public Object receiveRaw() throws Exception {
        ByteBuffer sizeBuf = ByteBuffer.allocate(4);
        while (sizeBuf.hasRemaining()) channel.read(sizeBuf);
        sizeBuf.flip();
        int len = sizeBuf.getInt();
        ByteBuffer dataBuf = ByteBuffer.allocate(len);
        while (dataBuf.hasRemaining()) channel.read(dataBuf);
        return Serializer.deserialize(dataBuf.array());
    }

    private byte[] sessionKey;
//    public void setSessionKey(byte[] key) { this.sessionKey = key; }
    public byte[] getSessionKey() { return sessionKey; }

    public boolean send(CommandRequest request) {
        try {
            byte[] payload;

            // Если рукопожатие завершено — шифруем, иначе отправляем как есть
            if (secureSerializer != null) {
                payload = secureSerializer.encryptAndSerialize(request);
            } else {
                payload = common.Serializer.serialize(request);
            }

            // Отправляем: 4 байта размер + payload
            ByteBuffer sizeBuffer = ByteBuffer.allocate(4);
            sizeBuffer.putInt(payload.length);
            sizeBuffer.flip();
            while (sizeBuffer.hasRemaining()) channel.write(sizeBuffer);

            ByteBuffer buffer = ByteBuffer.wrap(payload);
            while (buffer.hasRemaining()) channel.write(buffer);

            return true;
        } catch (Exception e) {
            System.out.println("Ошибка отправки: " + e.getMessage());
            return false;
        }
    }

    public CommandResponse receive() {
        try {
            // Читаем размер (4 байта)
            ByteBuffer sizeBuffer = ByteBuffer.allocate(4);
            while (sizeBuffer.hasRemaining()) {
                if (channel.read(sizeBuffer) == -1) {
                    System.out.println("Сервер закрыл соединение");
                    return null;
                }
            }
            sizeBuffer.flip();
            int dataSize = sizeBuffer.getInt();

            // Читаем payload
            ByteBuffer dataBuffer = ByteBuffer.allocate(dataSize);
            while (dataBuffer.hasRemaining()) {
                if (channel.read(dataBuffer) == -1) {
                    System.out.println("Сервер закрыл соединение при чтении");
                    return null;
                }
            }
            dataBuffer.flip();
            byte[] data = new byte[dataSize];
            dataBuffer.get(data);

            // Расшифровываем, если включено шифрование
            Object obj;
            if (secureSerializer != null) {
                obj = secureSerializer.decryptAndDeserialize(data);
            } else {
                obj = common.Serializer.deserialize(data);
            }

            return (CommandResponse) obj;
        } catch (Exception e) {
            System.out.println("Ошибка получения ответа: " + e.getMessage());
            return null;
        }
    }

    public void disconnect() {
        try {
            if (channel != null && channel.isOpen()) {
                channel.close();
                System.out.println("Отключено от сервера");
            }
        } catch (IOException e) {
            System.out.println("Ошибка при отключении: " + e.getMessage());
        }
    }

    public boolean isConnected() {
        return channel != null && channel.isOpen() && channel.isConnected();
    }

    public void setSessionKey(byte[] key) {
        if (key != null && key.length == 32) {
            this.secureSerializer = new SecureSerializer(key);
            System.out.println("AES-GCM шифрование включено");
        }
    }


}