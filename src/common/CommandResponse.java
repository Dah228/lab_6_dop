package common;

import common.Vehicle;
import java.io.Serializable;
import java.util.List;

public class CommandResponse implements Serializable {
    private static final long serialVersionUID = 1L;

    private boolean success;           // Успешно ли выполнилась команда
    private String message;            // Текстовое сообщение для пользователя
    private Object data;        // Данные (коллекция объектов)

    // Конструктор для команд с данными
    public CommandResponse(boolean success, String message, Object data) {
        this.success = success;
        this.message = message;
        this.data = data;
    }


    // Геттеры
    public boolean isSuccess() {
        return success;
    }

    public String getMessage() {
        return message;
    }

    public Object getData() {
        return data;
    }

}