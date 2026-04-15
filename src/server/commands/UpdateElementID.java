package server.commands;

import common.CommandType;
import common.Vehicle;
import common.ReturnCode;
import server.collection.VehicleManager;

public class UpdateElementID implements Command {
    VehicleManager vehicleManager;
    private final CommandType type = CommandType.WITHARGSMODEL;



    public UpdateElementID(VehicleManager vehicleManager) {
        this.vehicleManager = vehicleManager;
    }

    @Override
    public ReturnCode execute(CommandParams params) throws IllegalArgumentException {
        if (params.args().size() != 2){
            return ReturnCode.FAILED;
        }
//        try {
            long identifier = Long.parseLong(params.args().get(1));
            if (vehicleManager.updateElementByID(identifier, params.vehicle())) params.responseSender().send("Элемент успешно обновлен");
            return ReturnCode.OK;
//        } catch (IllegalArgumentException e) {
//            params.responseSender().send("Ошибка: неверный тип! Введите число");
//            return ReturnCode.FAILED;
//        }
    }

    public String getDescription(){
        return " обновить значение элемента коллекции, id которого равен заданному";
    }

    @Override
    public CommandType getType() {
        return this.type;
    }

}
