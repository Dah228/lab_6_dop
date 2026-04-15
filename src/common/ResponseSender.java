package common;

public interface ResponseSender {
    void send(String message);
    void sendError(String error);


    /** Получить накопленные сообщения */
    String getOutput();

    /** Очистить буфер */
    void clear();
}
