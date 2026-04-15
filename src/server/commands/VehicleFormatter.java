package server.commands;  // или common, если нужно и клиенту

import common.ResponseSender;
import common.Vehicle;

import java.util.Map;

/**
 * Утилиты для форматирования Vehicle в строки
 */
public class VehicleFormatter {

    /**
     * Форматирует один Vehicle и отправляет в ResponseSender
     */
    public static void printVehicle(Vehicle v, ResponseSender sender) {
        sender.send("ID: " + v.getId());
        sender.send("Name: " + v.getName());
        sender.send("Coordinates: (" + v.getCoordinates().getX() + ", " + v.getCoordinates().getY() + ")");
        sender.send("Creation date: " + v.getCreationDate());
        sender.send("Engine power: " + v.getEnginePower());
        sender.send("Distance travelled: " + v.getDistanceTravelled());
        sender.send("Type: " + v.getType());
        sender.send("Fuel type: " + v.getFuelType());
        sender.send("------------------------");
    }

    /**
     * Форматирует список Vehicle
     */
    public static void printVehicleList(java.util.ArrayList<Vehicle> vehicles, ResponseSender sender) {
        if (vehicles.isEmpty()) {
            sender.send("Коллекция пуста");
            return;
        }
        sender.send("Всего объектов: " + vehicles.size());
        sender.send("");
        for (Vehicle v : vehicles) {
            printVehicle(v, sender);
        }
    }

    public static void printGroupedResult(
            String fieldName,
            Map<Comparable<?>, Long> grouped,
            ResponseSender sender) {

        if (grouped.isEmpty()) {
            sender.send("Ничего не найдено");
            return;
        }

        sender.send("Группировка по полю: " + fieldName);
        sender.send("-------------------------------");

        grouped.forEach((key, count) ->
                sender.send(String.format("%s: %d объект(ов)",
                        key != null ? key.toString() : "[не задано]",
                        count))
        );

        long total = grouped.values().stream().mapToLong(Long::longValue).sum();
        sender.send("-------------------------------");
        sender.send("Всего сгруппировано: " + total);
    }
}

