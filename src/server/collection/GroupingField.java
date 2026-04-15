package server.collection;

import common.Vehicle;
import java.util.function.Function;

public record GroupingField(
        String fieldName,
        Function<Vehicle, Comparable<?>> extractor
) {}