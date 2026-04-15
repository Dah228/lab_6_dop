package server.service;

import common.ResponseSender;

public class NetworkResponseSender implements ResponseSender {
    private final StringBuilder output = new StringBuilder();

    @Override
    public void send(String message) {
        output.append(message).append("\n");
    }

    @Override
    public void sendError(String error) {
        output.append("ERROR").append(error).append("\n");
    }

    @Override
    public String getOutput() {
        String result = output.toString();
        clear(); // очищаем после чтения
        return result;
    }

    @Override
    public void clear() {
        output.setLength(0);
    }
}