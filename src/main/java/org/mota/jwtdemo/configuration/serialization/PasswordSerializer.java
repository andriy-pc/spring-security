package org.mota.jwtdemo.configuration.serialization;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import java.io.IOException;

public class PasswordSerializer extends StdSerializer<String> {

  protected PasswordSerializer() {
    super(String.class);
  }

  @Override
  public void serialize(String s, JsonGenerator jsonGenerator,
      SerializerProvider serializerProvider) throws IOException {
    jsonGenerator.writeString("******");
  }
}
