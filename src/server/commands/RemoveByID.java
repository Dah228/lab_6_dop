package server.commands;

import common.CommandType;
import common.ReturnCode;
import server.collection.VehicleManager;

public class RemoveByID implements Command{
    VehicleManager vehicleManager;
    private final CommandType type = CommandType.WITHARGS;


    public RemoveByID(VehicleManager vehicleManager){
        this.vehicleManager = vehicleManager;
    }

    @Override
    public ReturnCode execute(CommandParams params) throws IllegalArgumentException {
        if(params.args().size() != 2) return ReturnCode.FAILED;
//        try {
            long number = Long.parseLong(params.args().get(1));
            if (vehicleManager.rmByID(number)) params.responseSender().send("Успешно удален");
            return ReturnCode.OK;
//        } catch (IllegalArgumentException e) {
//            if(params.isLaud()) params.responseSender().send("Ошибка: неверный тип! Введите число");
//            return ReturnCode.FAILED;
//        }
    }


    @Override
    public String getDescription(){
        return " удалить элемент из коллекции по его id";
    }

    @Override
    public CommandType getType() {
        return this.type;
    }
}
