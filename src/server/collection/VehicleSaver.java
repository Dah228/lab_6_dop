package server.collection;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import common.Vehicle;


import java.text.SimpleDateFormat;
import java.util.TimeZone;

public class VehicleSaver {
    private final VehicleCollection collection;

    public VehicleSaver(VehicleCollection collection) {
        this.collection = collection;
    }

    public boolean saveToFile() {

        try {

            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            DocumentBuilder builder = factory.newDocumentBuilder();

            // Create a new Document
            Document document = builder.newDocument();

            // Create root element
            Element root = document.createElement("vehicles");
            document.appendChild(root);

            // Create book elements and add text content
            for (Vehicle v : collection.getVehicles()) {
                Element vehicleElem = document.createElement("vehicle");

                vehicleElem.setAttribute("id", String.valueOf(v.getId()));

                Element nameElem = document.createElement("name");
                nameElem.setTextContent(v.getName());
                vehicleElem.appendChild(nameElem);

                Element coords = document.createElement("coordinates");
                Element xelem = document.createElement("x");
                xelem.setTextContent(String.valueOf(v.getCoordinates().getX()));
                Element yelem = document.createElement("y");
                yelem.setTextContent(String.valueOf(v.getCoordinates().getY()));
                coords.appendChild(xelem);
                coords.appendChild(yelem);
                vehicleElem.appendChild(coords);

                Element date = document.createElement("creationDate");
                SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");
                sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
                date.setTextContent(sdf.format(v.getCreationDate()));
                vehicleElem.appendChild(date);

                Element power = document.createElement("enginePower");
                power.setTextContent(String.valueOf(v.getEnginePower()));
                vehicleElem.appendChild(power);

                Element dist = document.createElement("distanceTravelled");
                dist.setTextContent(String.valueOf(v.getDistanceTravelled()));
                vehicleElem.appendChild(dist);

                Element type = document.createElement("type");
                type.setTextContent(v.getType() != null ? v.getType().name() : "");
                vehicleElem.appendChild(type);

                Element fuel = document.createElement("fuelType");
                fuel.setTextContent(String.valueOf(v.getFuelType()));
                vehicleElem.appendChild(fuel);

                root.appendChild(vehicleElem);
            }

            // Write to XML file
            TransformerFactory transformerFactory = TransformerFactory.newInstance();
            Transformer transformer = transformerFactory.newTransformer();
            DOMSource source = new DOMSource(document);

            // Specify your local file path
            StreamResult result = new StreamResult("vehicles_saved.xml");
            transformer.transform(source, result);
            return true;
        } catch (ParserConfigurationException | TransformerException e) {
            return false;
        }

    }
}

