package server.service;

import common.FuelType;
import common.Vehicle;
import common.VehicleType;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.TimeZone;

public class Parser {

    public static ArrayList<Vehicle> parse(String filePath) throws Exception {
        ArrayList<Vehicle> list = new ArrayList<>();
        InputStreamReader isr = new InputStreamReader(new FileInputStream(filePath), StandardCharsets.UTF_8);

        DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
        DocumentBuilder b = f.newDocumentBuilder();
        Document doc = b.parse(new InputSource(isr));
        isr.close();

        NodeList n = doc.getElementsByTagName("vehicle");
        for (int i = 0; i < n.getLength(); i++) {
            try {
                Element e = (Element) n.item(i);
                Vehicle v = new Vehicle();

                // Парсинг имени
                String name = e.getElementsByTagName("name").item(0).getTextContent();
                v.setName(name);

                // Парсинг координат
                Element c = (Element) e.getElementsByTagName("coordinates").item(0);
                int x = Integer.parseInt(c.getElementsByTagName("x").item(0).getTextContent());
                float y = Float.parseFloat(c.getElementsByTagName("y").item(0).getTextContent());
                v.setCoordinates(x, y);

                // Парсинг даты
                String dateStr = e.getElementsByTagName("creationDate").item(0).getTextContent().trim();
                try {
                    SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");
                    sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
                    Date parsedDate = sdf.parse(dateStr);
                    v.setCreationDateHand(parsedDate);
                } catch (ParseException ec) {
                    v.setCreationDate(); // Если дата неверная, ставим текущую
                }

                // Парсинг числовых полей
                v.setEnginePower(Float.parseFloat(e.getElementsByTagName("enginePower").item(0).getTextContent()));
                v.setDistanceTravelled(Float.parseFloat(e.getElementsByTagName("distanceTravelled").item(0).getTextContent()));

                // Парсинг типа (может быть null)
                var typeNode = e.getElementsByTagName("type").item(0);
                if (typeNode != null && !typeNode.getTextContent().trim().isEmpty()) {
                    v.setType(VehicleType.valueOf(typeNode.getTextContent().trim().toUpperCase()));
                } else {
                    v.setType(null);
                }

                // Парсинг типа топлива
                v.setFuelType(FuelType.valueOf(e.getElementsByTagName("fuelType").item(0).getTextContent().trim().toUpperCase()));

                // Валидация объекта
                if (v.getName() == null || v.getName().trim().isEmpty() ||
                        v.getCoordinates() == null ||
                        v.getCoordinates().getY() <= -668F ||
                        v.getEnginePower() <= 0 ||
                        v.getDistanceTravelled() <= 0) {
                    throw new IllegalArgumentException("Некорректные данные объекта");
                }

                list.add(v);

            } catch (Exception e) {
                System.out.println("Объект номер " + (i + 1) + " пропущен (ошибка валидации или структуры XML)");
            }
        }
        return list;
    }
}