package server.service;

import common.Vehicle;
import server.commands.Invoker;

import java.io.File;
import java.util.ArrayList;

public class XmlDataLoader {

    public static void loadAndRegister(String xmlFilePath, Invoker invoker) {
        if (xmlFilePath == null || xmlFilePath.isEmpty()) {
            return;
        }
        try {
            File xmlFile = new File(xmlFilePath);
            if (xmlFile.exists()) {
                System.out.println("Найден файл: " + xmlFilePath);
                ArrayList<Vehicle> vehicles = Parser.parse(xmlFilePath);
                for (Vehicle v : vehicles) {
                    invoker.executeCommand("add", null, v, false, null);
                }
            }
        } catch (Exception e) {
            System.err.println("Ошибка при парсинге файла: " + e.getMessage());
        }
    }
}