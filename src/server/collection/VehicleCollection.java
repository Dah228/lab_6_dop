package server.collection;

import common.Vehicle;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

public class VehicleCollection {
    private final CopyOnWriteArrayList<Vehicle> vehicles = new CopyOnWriteArrayList<>();
    private final Instant initTime = Instant.now();

    // Методы изменения данных
    public void add(Vehicle v) {
        vehicles.add(v);
    }


    public void clear() {
        vehicles.clear();
    }

    // Методы доступа к данным (для Менеджера)
    public ArrayList<Vehicle> getVehicles() {
        return new ArrayList<>(vehicles);
    }

    public int size() {
        return vehicles.size();
    }

    public Instant getInitTime() {
        return initTime;
    }

    public boolean isEmpty() {
        return vehicles.isEmpty();
    }

    public void rmEl(Vehicle v) {
        vehicles.remove(v);
    }

    public List<Long> getAllID() {
        List<Long> id = new ArrayList<>();
        for (Vehicle v : vehicles) {
            id.add(v.getId());
        }
        return id;
    }

    public Vehicle getVehicleByID(long id) {
        for (Vehicle v : vehicles) {
            if (v.getId() == id) {
                return v;
            }
        }
        return null;
    }

    public void replaceVehicle(long id, Vehicle vehicle) {
        int index = (int) id - 1;
        if (index >= 0 && index < vehicles.size()) {
            vehicles.set(index, vehicle);
        }
    }
}