package server.commands;

import common.ResponseSender;
import common.Vehicle;

import java.util.List;

/**
 * Параметры выполнения команды — легко расширять новыми полями
 */
public record CommandParams(
        List<String> args,
        Vehicle vehicle,
        Boolean isLaud,
        ResponseSender responseSender  // ← добавляем отправщик сюда!
) {}