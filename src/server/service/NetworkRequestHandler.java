package server.service;

import common.CommandRequest;
import common.CommandResponse;
import common.ReturnCode;
import server.commands.Invoker;

import java.nio.channels.SocketChannel;

public class NetworkRequestHandler {

    private final Invoker invoker;
    private final ServerNetworkService networkService;

    public NetworkRequestHandler(Invoker invoker, ServerNetworkService networkService) {
        this.invoker = invoker;
        this.networkService = networkService;
    }

    public void processRequest(SocketChannel clientChannel, CommandRequest request) {
        try {
            String commandName = request.getCommandName();
            var arguments = request.getArguments();
            var vehicle = request.getVehicle();
            var isLaud = request.getBoolean();

            System.out.printf("Запрос от %s: %s%n",
                    clientChannel.getRemoteAddress(), commandName);

            NetworkResponseSender networkSender = new NetworkResponseSender();

            ReturnCode statusCode = invoker.executeCommand(
                    commandName,
                    arguments,
                    vehicle,
                    isLaud,
                    networkSender
            );

            String commandOutput = networkSender.getOutput();

            CommandResponse response = new CommandResponse(
                    statusCode == ReturnCode.OK,
                    commandOutput.isEmpty() ? "Команда выполнена" : commandOutput,
                    null
            );

            networkService.sendTo(clientChannel, response);

        } catch (Exception e) {
            System.err.println("Ошибка обработки запроса: " + e.getMessage());
            CommandResponse error = new CommandResponse(
                    false,
                    "Ошибка сервера: " + e.getMessage(),
                    null
            );
            networkService.sendTo(clientChannel, error);
        }
    }
}