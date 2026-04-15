package server.commands;

import common.CommandType;
import server.collection.VehicleSaver;
import common.ReturnCode;

public class SaveCommand implements Command{
    VehicleSaver vehicleSaver;
    private final CommandType type = CommandType.NOARGS;


    public SaveCommand(VehicleSaver vehicleSaver){
        this.vehicleSaver = vehicleSaver;
    }

@Override
    public ReturnCode execute(CommandParams params){
        if (params.args().size()!= 1) return ReturnCode.FAILED;
        if(vehicleSaver.saveToFile()) {
            params.responseSender().send("Успешно сохранено vehicles_saved");
            return ReturnCode.OK;
        }
        else{
            params.responseSender().send("Произошла ошибка сохранения");
            return ReturnCode.FAILED;
        }
    }

    @Override
    public String getDescription() {
        return " сохранить коллекцию в файл";
    }

    @Override
    public CommandType getType() {
        return this.type;
    }
}
