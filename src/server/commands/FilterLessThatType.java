package server.commands;


import common.*;
import server.collection.VehicleManager;

import java.util.ArrayList;

import static server.commands.VehicleFormatter.printVehicleList;

public class FilterLessThatType implements Command{

    private final CommandType type = CommandType.WITHARGS;
    VehicleManager vehicleManager;

    public FilterLessThatType(VehicleManager vehicleCollection){
        this.vehicleManager = vehicleCollection;
    }

    @Override
    public ReturnCode execute(CommandParams params) throws IllegalArgumentException{
        if (params.args().size() != 2) return ReturnCode.FAILED;
//        try {
            VehicleType type = VehicleType.valueOf(params.args().get(1).toUpperCase());
            ArrayList<Vehicle> veh = vehicleManager.filterLessThanType(type);
            if (params.isLaud()) printVehicleList(veh, params.responseSender());
            return ReturnCode.OK;
//        } catch (IllegalArgumentException e) {
//            if(params.isLaud()) params.responseSender().send("Ошибка: неверный тип! Доступные: PLANE, HELICOPTER, BOAT, SHIP, HOVERBOARD");
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
