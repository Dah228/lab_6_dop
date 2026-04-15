package server.commands;

import common.CommandType;
import common.ReturnCode;
import server.collection.VehicleManager;

public class AddIfMax implements Command{
    VehicleManager vehicleAdder;
    private final CommandType type = CommandType.WITHMODEL;


    public AddIfMax(VehicleManager vehicleComaperator){
        this.vehicleAdder = vehicleComaperator;
    }


    @Override
    public ReturnCode execute(CommandParams params) throws IllegalArgumentException {
        if (params.args().size() != 1){
            return ReturnCode.FAILED;
        }
            vehicleAdder.addIfMax(params.vehicle());
            if (params.isLaud()) params.responseSender().send("У элемента максимальное значение пройденной дистанции. Добавлен.");
            return ReturnCode.OK;
    }

    @Override
    public String getDescription() {
        return "добавить новый элемент в коллекцию, если его значение превышает значение наибольшего элемента этой коллекции";
    }

    @Override
    public CommandType getType(){
        return this.type;
    }

}

