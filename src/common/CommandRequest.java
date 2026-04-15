package common;

import java.io.Serial;
import java.io.Serializable;
import java.util.List;


public class CommandRequest implements Serializable {
    @Serial
    private static final long serialVersionUID = 1L;
    private String commandname;
    private List<String> args;
    private Vehicle vehicle;
    private boolean islaud;
    public CommandRequest(String commandname, List<String> args, Vehicle vehicle, boolean islaud){
        this.commandname = commandname;
        this.args = args;
        this.vehicle = vehicle;
        this.islaud = islaud;
    }


    public String getCommandName() { return commandname; }
    public List<String> getArguments(){return args;}
    public boolean getBoolean(){return islaud;}
    public Vehicle getVehicle() { return vehicle; }


}
