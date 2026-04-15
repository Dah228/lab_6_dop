package server.collection;


import common.Vehicle;


import java.util.List;

public class ValidateParams {

    private final List<String> args;

    public ValidateParams(List<String> args) {
        if (args == null || args.isEmpty()) {
            throw new IllegalArgumentException("Нет аргументов");
        }
        this.args = args;
    }

    public GroupingField getGroupingField() {
        String first = args.get(1).trim().toUpperCase();

        // 1. VehicleType
        return switch (first) {
            case "TYPE" -> new GroupingField("type", Vehicle::getType);


            // 2. FuelType
            case "FUELTYPE" -> new GroupingField("fueltype", Vehicle::getFuelType);


            // 3. Координаты
            case "COORDINATES" -> new GroupingField("coordinates", Vehicle::getCoordinates);
            default -> throw new IllegalArgumentException("Не распознано: " + first);
        };

    }
}
