package server.collection;


import common.Vehicle;
import common.VehicleType;

import java.util.*;
import java.util.stream.Collectors;


public class VehicleManager {
    private final VehicleCollection collection;

    // Конструктор с внедрением зависимости
    public VehicleManager(VehicleCollection collection) {
        this.collection = collection;
    }

    // Логика вывода всей коллекции
    public ArrayList<Vehicle> showCollection() {
        return collection.getVehicles();
    }


    // Логика информации
    public HashMap<String, String> getInfo() {
        HashMap<String, String> paramList = new HashMap<>();
        paramList.put("Размер коллекции : ", String.valueOf(collection.size()));
        paramList.put("Тип коллекции : ", collection.getVehicles().getClass().getName());
        paramList.put("Дата инициализации : ", String.valueOf(collection.getInitTime()));
        float summa = 0;
        for (Vehicle v : collection.getVehicles()) {
            summa += v.getEnginePower();
        }
        paramList.put("Общая мощность двигателей : ", String.valueOf(summa));

        if (!collection.isEmpty()) {
            paramList.put("Средняя мощность двигателя : ", String.valueOf(summa / collection.size()));
        } else {
            paramList.put("Средняя мощность двигателя", "0 (коллекция пуста)");
        }

        return paramList;
    }

    // Логика фильтрации
    public ArrayList<Vehicle> filterByEnginePower(Float power) {
        ArrayList<Vehicle> filteredByEngine = new ArrayList<>();
        for (Vehicle v : collection.getVehicles()) {
            if (v.getEnginePower() >= power) {
                filteredByEngine.add(v);
            }
        }
        return filteredByEngine;
    }

    // Логика очистки
    public void clearCollection() {
        collection.clear();
    }


    public ArrayList<Vehicle> filterLessThanType(VehicleType type) {
        ArrayList<Vehicle> filteredByEngine = new ArrayList<>();
        for (Vehicle v : collection.getVehicles()) {
            if (v.getType().compareTo(type) < 0) {
                filteredByEngine.add(v);
            }
        }
        return filteredByEngine;
    }

    public boolean updateElementByID(long id, Vehicle vehicle) {
        if (collection.getVehicleByID(id) != null) {
            vehicle.setId(id);
            collection.replaceVehicle(id, vehicle);
            return true;
        }
        return false;  // ← не найдено
    }

    public boolean rmByID(long id) {
        List<Long> ids = collection.getAllID();
        for (Long i : ids) {
            if (i.equals(id)) {
                collection.rmEl(collection.getVehicleByID(id));
                return true;
            }
        }
        return false;
    }

    public void addElement(Vehicle vehicle) {
        collection.add(vehicle);
    }

    public boolean addIfMax(Vehicle veh) {
        if (collection.getVehicles().stream().allMatch(v ->
                v.getDistanceTravelled() < veh.getDistanceTravelled())) {
            collection.add(veh);
            return true;
        }
        return false;
    }

    // ← groupByParam возвращает результат, а не печатает
    public Map<Comparable<?>, Long> groupByParam(List<String> args) {
        ValidateParams validator = new ValidateParams(args);
        GroupingField field = validator.getGroupingField();

        return collection.getVehicles().stream()
                .collect(Collectors.groupingBy(
                        field.extractor(),
                        Collectors.counting()
                ));
    }

    public ArrayList<Vehicle> sortByID() {
        ArrayList<Vehicle> vehicles = collection.getVehicles();
        vehicles.sort(Comparator.comparingLong(Vehicle::getId));
        return vehicles;
    }

    public ArrayList<Vehicle> sortByIDDescending() {
        ArrayList<Vehicle> vehicles = collection.getVehicles();
        vehicles.sort(Comparator.comparingLong(Vehicle::getId).reversed());
        return vehicles;
    }

    public ArrayList<Vehicle> shuffle() {
        ArrayList<Vehicle> vehicles = collection.getVehicles();
        Collections.shuffle(vehicles);
        return vehicles;
    }


}