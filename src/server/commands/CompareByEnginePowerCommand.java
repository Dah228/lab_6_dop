package server.commands;

import common.CommandType;
import common.ReturnCode;
import common.Vehicle;
import server.collection.VehicleManager;

import java.util.ArrayList;


import static server.commands.VehicleFormatter.printVehicleList;

public class CompareByEnginePowerCommand implements Command {
    private final VehicleManager vehicleManager;
    private final CommandType type = CommandType.WITHARGS;


    public CompareByEnginePowerCommand(VehicleManager vehicleCollection) {
        this.vehicleManager = vehicleCollection;
    }

    @Override
    public ReturnCode execute(CommandParams params) throws IllegalArgumentException {
        if (params.args().size() != 2) {
            return ReturnCode.FAILED;
        }
//        try {
            Float number = Float.parseFloat(String.valueOf(params.args().get(1)));
            ArrayList<Vehicle> veh = vehicleManager.filterByEnginePower(number);
            if (params.isLaud()) printVehicleList(veh, params.responseSender());
            return ReturnCode.OK;
//        } catch (IllegalArgumentException e) {
//            if (params.isLaud()) params.responseSender().send("Ошибка: неверный тип! Введите число");
//            return ReturnCode.FAILED;
//        }
    }


    @Override
    public String getDescription() {
        return "вывести элементы, значение поля enginePower которых больше заданного";
    }

    @Override
    public CommandType getType() {
        return this.type;
    }
}
