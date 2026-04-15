package server.commands;

import common.CommandType;
import server.collection.VehicleManager;
import common.ReturnCode;

public class InfoCommand implements Command{
    private final VehicleManager vehicleCollection;
    private final CommandType type = CommandType.NOARGS;



    public InfoCommand(VehicleManager vehicleCollection) {
        this.vehicleCollection = vehicleCollection;
    }

    @Override
    public ReturnCode execute(CommandParams params) {
        if (params.args().size() != 1) return ReturnCode.FAILED;

        else {
            vehicleCollection.getInfo().forEach((key, value) -> params.responseSender().send(key + value));
            return ReturnCode.OK;
        }
    }

    @Override
    public String getDescription() {
        return " вывести в стандартный поток информацию о коллекции";
    }

    @Override
    public CommandType getType() {
        return this.type;
    }

}
