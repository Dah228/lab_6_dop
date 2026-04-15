package common;



import java.io.Serializable;
import java.util.Date;


public class Vehicle implements Serializable {
    private static long currentId = 1;

    private long id;
    private String name;
    private Coordinates coordinates;
    private Date creationDate;
    private float enginePower;
    private float distanceTravelled;
    private VehicleType type;
    private FuelType fuelType;

    public Vehicle() {
        this.id = currentId++;
        this.creationDate = new java.util.Date();
    }

    public long getId(){
        return id;
    }

    public String getName(){
        return this.name;
    }

    public Coordinates getCoordinates(){
        return this.coordinates;
    }
    public Date getCreationDate(){
        return this.creationDate;
    }
    public float getEnginePower(){
        return this.enginePower;
    }
    public VehicleType getType(){
        return this.type;
    }

    public float getDistanceTravelled(){
        return this.distanceTravelled;
    }

    public FuelType getFuelType(){
        return this.fuelType;
    }

    public  void setCreationDate(){
        long fiveYearsInMillis = 5L * 365 * 24 * 60 * 60 * 1000;
        long randomMillis = System.currentTimeMillis() -
                (long) (Math.random() * fiveYearsInMillis);
        this.creationDate = new Date(randomMillis);
    }




    public void setCreationDateHand(Date data){
        this.creationDate = data;
    }

    public void setId(long id){
        this.id = id;
    }

    public void setName(String name){
        this.name = name;
    }

    public void setCoordinates(int x, float y) {
        if (this.coordinates == null) {
            this.coordinates = new Coordinates();
        }
        this.coordinates.setCoord(x,y);
    }


    public void setEnginePower(Float power){
        if (power>0){ this.enginePower = power;}
        else {System.out.println("Мощность двигателя не может быть отрицательной");}
    }
    public void setType(VehicleType type){
        this.type = type;
    }

    public void setDistanceTravelled(float distanceTravelled){
        this.distanceTravelled = distanceTravelled;
    }

    public void setFuelType(FuelType fuel){
        this.fuelType = fuel;
    }


}

