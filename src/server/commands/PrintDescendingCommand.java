package server.commands;

import common.CommandType;
import common.Vehicle;
import server.collection.VehicleManager;
import common.ReturnCode;
import java.util.ArrayList;

import static server.commands.VehicleFormatter.printVehicleList;

public class PrintDescendingCommand implements Command{
    private final VehicleManager vehicleRandom;
    private final CommandType type = CommandType.NOARGS;

    public PrintDescendingCommand(VehicleManager vehicleRandom){
        this.vehicleRandom = vehicleRandom;
    }

    @Override
    public ReturnCode execute(CommandParams params){
        if (params.args().size() != 1) return ReturnCode.FAILED;
        else{
            ArrayList<Vehicle> veh = vehicleRandom.sortByIDDescending();
            if (params.isLaud()) printVehicleList(veh, params.responseSender());
            return ReturnCode.OK;
        }

    }

    @Override
    public String getDescription(){
        return "вывести элементы коллекции в порядке убывания";
    }

    @Override
    public CommandType getType() {
        return this.type;
    }
}
