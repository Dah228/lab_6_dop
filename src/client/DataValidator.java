package client;

import common.FuelType;
import common.Vehicle;
import common.VehicleType;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.util.NoSuchElementException;

public class DataValidator {
    private BufferedReader reader;
    private Boolean isLaud;

    public DataValidator(InputStream inputStream, Boolean isLaud) {
        this.reader = new BufferedReader(new InputStreamReader(inputStream));
        this.isLaud = isLaud;
    }

    public void setInputStream(InputStream inputStream) {
        this.reader = new BufferedReader(new InputStreamReader(inputStream));
    }

    private <T> T readValidatedInput(
            String prompt,
            Boolean isLaud,
            java.util.function.Function<String, T> parser,
            String errorMsg
    ) {
        if (isLaud) {
            while (true) {
                System.out.println(prompt);
                try {
                    String input = reader.readLine();
                    if (input == null) throw new NoSuchElementException("Конец потока");
                    input = input.trim();
                    return parser.apply(input);
                } catch (IllegalArgumentException e) {
                    System.out.println(errorMsg);
                } catch (IOException e) {
                    throw new NoSuchElementException("Ошибка ввода");
                }
            }
        } else {
            try {
                while (true) {
                    String input = reader.readLine();
                    if (input == null) throw new NoSuchElementException("Конец файла");
                    input = input.trim();
                    if (input.isEmpty()) continue;
                    return parser.apply(input);
                }
            } catch (IOException e) {
                throw new NoSuchElementException("Ошибка чтения");
            }
        }
    }

    public Integer readValidInteger(String prompt, Boolean isLaud) {
        return readValidatedInput(prompt, isLaud, Integer::valueOf, "Ошибка: ожидалось целое число");
    }

    public Float readValidFloat(String prompt, Float min, Boolean isLaud) {
        return readValidatedInput(
                prompt, isLaud,
                s -> {
                    float val = Float.parseFloat(s);
                    if (val <= min) throw new IllegalArgumentException();
                    return val;
                },
                "Ошибка: число должно быть > " + min
        );
    }

    public VehicleType readVehicleType(String prompt, Boolean isLaud) {
        return readValidatedInput(
                prompt, isLaud,
                s -> s.isEmpty() ? null : VehicleType.valueOf(s.toUpperCase()),
                "Неверный тип! Доступны: " + Arrays.toString(VehicleType.values())
        );
    }

    public FuelType readFuelType(String prompt, Boolean isLaud) {
        return readValidatedInput(
                prompt, isLaud,
                s -> FuelType.valueOf(s.toUpperCase()),
                "Неверный тип! Доступны: " + Arrays.toString(FuelType.values())
        );
    }

    private boolean isValidForXml(String text) {
        for (char c : text.toCharArray()) {
            if (c == '<' || c == '>' || c == '&' || c == '"' || c == '\'') return false;
        }
        return true;
    }

    public String readValidName(String prompt, Boolean isLaud) {
        return readValidatedInput(
                prompt, isLaud,
                s -> {
                    if (!isValidForXml(s) || s.isEmpty()) {
                        throw new IllegalArgumentException("XML-unsafe символы");
                    }
                    return s;
                },
                "Имя содержит недопустимые символы"
        );
    }

    public Vehicle parseVehicle(Boolean isLaud) {
        Vehicle veh = new Vehicle();
        veh.setName(readValidName("Введите имя: ", isLaud));
        veh.setCreationDate();
        veh.setCoordinates(
                readValidInteger("Введите X (целое число): ", isLaud),
                readValidFloat("Введите Y (> -668): ", -668F, isLaud)
        );
        veh.setEnginePower(readValidFloat("Введите мощность двигателя (> 0): ", 0f, isLaud));
        veh.setDistanceTravelled(readValidFloat("Введите пройденное расстояние (> 0): ", 0f, isLaud));
        veh.setType(readVehicleType("Введите тип (PLANE, HELICOPTER, BOAT, SHIP, HOVERBOARD) или пустую строку: ", isLaud));
        veh.setFuelType(readFuelType("Введите тип топлива (GASOLINE, KEROSENE, ELECTRICITY, DIESEL, NUCLEAR):", isLaud));
        return veh;
    }
}