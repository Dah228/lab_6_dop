package common;


import java.io.Serializable;

import static java.lang.Math.sqrt;

public class Coordinates implements Comparable<Coordinates>, Serializable {
    int x;
    float y;

    public int getX(){
        return this.x;
    }
    public float getY(){
        return this.y;
    }



public void setCoord(int x, float y){
        this.x = x;
        this.y = y;
    }

    @Override
    public int compareTo(Coordinates other) {
        return Double.compare(this.x * this.x + this.y * this.y, other.x*other.x + other.y * other.y);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (!(obj instanceof Coordinates that)) return false;

        double thisDist;
        thisDist = sqrt(this.x * this.x + this.y * this.y);
        double thatDist = sqrt(that.x * that.x + that.y * that.y);

        return Math.abs(thisDist - thatDist) < 0.001;
    }

}

