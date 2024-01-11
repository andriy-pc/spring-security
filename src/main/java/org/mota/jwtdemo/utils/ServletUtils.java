package org.mota.jwtdemo.utils;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletResponse;
import lombok.SneakyThrows;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;

public final class ServletUtils {
    private ServletUtils() {

    }

    private static final ObjectMapper DEFAULT_OBJECT_MAPPER = new ObjectMapper();

    @SneakyThrows
    public static void setResponseStatus(final HttpServletResponse response, HttpStatus httpStatus, final String responseMessage) {
        response.setStatus(httpStatus.value());
        response.setHeader("Content-Type", MediaType.APPLICATION_JSON_VALUE);
        var responseNode = DEFAULT_OBJECT_MAPPER.createObjectNode();
        responseNode.put("status", httpStatus.value());
        responseNode.put("message", responseMessage);
        DEFAULT_OBJECT_MAPPER.writeValue(
                response.getOutputStream(), responseNode);
    }
}
