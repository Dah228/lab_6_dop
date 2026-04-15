package server.service;

import common.CommandRequest;

import java.nio.channels.SelectionKey;
import java.nio.channels.SocketChannel;
import java.util.List;

public class ServerLoop {

    private final ServerContext context;
    private final NetworkRequestHandler requestHandler;
    private volatile boolean running = true;

    public ServerLoop(ServerContext context, NetworkRequestHandler requestHandler) {
        this.context = context;
        this.requestHandler = requestHandler;
    }

    public void stop() {
        running = false;
    }

    public void run() {
        ServerNetworkService network = context.getNetworkService();

        while (running) {

            List<SelectionKey> readyKeys = network.processEvents();

            for (SelectionKey key : readyKeys) {
                CommandRequest request = (CommandRequest) key.attachment();
                key.attach(null); // сбрасываем, чтобы не обработать повторно

                requestHandler.processRequest((SocketChannel) key.channel(), request);
            }

        }
    }
}