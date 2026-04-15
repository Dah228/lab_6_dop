package server.commands;

import common.CommandType;
import common.ReturnCode;
import common.Vehicle;
import server.collection.VehicleManager;

import java.util.Map;


public class GroupByCommand implements Command{
    private final VehicleManager vehicleAdder;
    private final CommandType type = CommandType.DETECTPARAM;
    public GroupByCommand(VehicleManager vehicleAdder){
        this.vehicleAdder = vehicleAdder;
    }

        @Override
        public ReturnCode execute(CommandParams params) {
//            try {

                Map<Comparable<?>, Long> grouped = vehicleAdder.groupByParam(params.args());
                String fieldName = params.args().get(0);
                VehicleFormatter.printGroupedResult(fieldName, grouped, params.responseSender());
                return ReturnCode.OK;
//
//            } catch (Exception e) {
//                params.responseSender().send(" Ошибка группировки: " + e.getMessage());
//                return ReturnCode.FAILED;
//            }
        }

    @Override
    public String getDescription() {
        return "сгруппировать элементы по заданному типу";
    }


    @Override
    public CommandType getType() {
        return this.type;
    }



}
