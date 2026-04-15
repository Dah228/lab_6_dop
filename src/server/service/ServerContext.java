package server.service;

import server.commands.CommandsList;
import server.commands.Invoker;

public class ServerContext {
    private final CommandsList commandsList;
    private final Invoker invoker;
    private final ServerNetworkService networkService;
    private final String xmlFilePath;
    private final int port;

    public ServerContext(int port, String xmlFilePath) {
        this.port = port;
        this.xmlFilePath = xmlFilePath;
        this.commandsList = new CommandsList();
        this.invoker = commandsList.getInvoker();
        this.networkService = new ServerNetworkService(port, commandsList);
    }

    public boolean startNetwork() {
        return networkService.start();
    }

    public CommandsList getCommandsList() { return commandsList; }
    public Invoker getInvoker() { return invoker; }
    public ServerNetworkService getNetworkService() { return networkService; }
    public String getXmlFilePath() { return xmlFilePath; }
    public int getPort() { return port; }

    public void stop() {
        if (networkService != null) {
            networkService.stop();
        }
    }
}