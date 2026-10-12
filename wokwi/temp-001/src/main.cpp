#include <Arduino.h>
#include <DHT.h>

#define DHT_PIN 4
#define DHT_TYPE DHT22

DHT dht(DHT_PIN, DHT_TYPE);

void setup() {
  Serial.begin(115200);

  dht.begin();

  Serial.println("SecureSense TEMP-001");
  Serial.println("Temperature sensor starting...");
}

void loop() {
  const float temperature = dht.readTemperature();

  if (isnan(temperature)) {
    Serial.println("ERROR: Failed to read temperature");
    delay(2000);
    return;
  }

  Serial.print("TEMP-001 temperature=");
  Serial.print(temperature);
  Serial.println(" C");

  delay(2000);
}
