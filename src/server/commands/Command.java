    package server.commands;

    import common.CommandType;
    import common.ReturnCode;

    public interface Command {
        ReturnCode execute(CommandParams params) throws Exception;
        String getDescription();
        CommandType getType();
    }
