package server.commands;

import common.CommandType;
import server.collection.VehicleManager;
import common.ReturnCode;


import static server.commands.VehicleFormatter.printVehicleList;

public class SortCommand implements Command{
    private final VehicleManager vehicleRandom;
    private final CommandType type = CommandType.NOARGS;

    public SortCommand(VehicleManager vehicleRandom){
        this.vehicleRandom = vehicleRandom;
    }

    @Override
    public ReturnCode execute(CommandParams params) {
        if (params.args().size() != 1) return ReturnCode.FAILED;
        else {
            printVehicleList(vehicleRandom.sortByID(), params.responseSender());
            return ReturnCode.OK;
        }
    }

    @Override
    public String getDescription(){
        return " отсортировать коллекцию в естественном порядке";
    }

    @Override
    public CommandType getType() {
        return this.type;
    }


}
