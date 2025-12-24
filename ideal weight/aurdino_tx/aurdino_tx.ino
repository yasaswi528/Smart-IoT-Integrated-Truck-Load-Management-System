#include <Wire.h>
#include <Adafruit_Sensor.h>
#include <Adafruit_BMP280.h>
#include "HX711.h"
#include <LiquidCrystal_I2C.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <SPI.h>
#include <LoRa.h>

// WiFi credentials
const char* ssid = "purple";
const char* password = "1234567890";

// ThingSpeak API
const char* apiKey = "TQVFVC5V8RJ3P7C4"; // Write API Key
const char* server = "https://api.thingspeak.com/update"; // HTTPS endpoint

// BMP280
Adafruit_BMP280 bmp;

// HX711
#define DOUT 13
#define CLK 12
HX711 scale;
float calibration_factor = 1100.0;
long weight;

// LCD
LiquidCrystal_I2C lcd(0x27, 16, 2);

// LoRa pins
#define LORA_SCK 18
#define LORA_MISO 19
#define LORA_MOSI 23
#define LORA_SS 4
#define LORA_RST 5
#define LORA_DIO0 2

float temperature, pressure, altitude;

void connectWiFi() {
  if (WiFi.status() != WL_CONNECTED) {
    Serial.print("Connecting to WiFi");
    WiFi.begin(ssid, password);
    while (WiFi.status() != WL_CONNECTED) {
      delay(500);
      Serial.print(".");
    }
    Serial.println("\nWiFi Connected!");
    lcd.clear();
    lcd.print("WiFi Connected");
  }
}

void setup() {
  Serial.begin(115200);
  Wire.begin();
  lcd.init(); 
  lcd.backlight();
  lcd.setCursor(0, 0);
  lcd.print("Initializing...");

  // BMP280 init
  if (!bmp.begin(0x76)) {
    lcd.clear();
    lcd.print("BMP280 Error");
    Serial.println("BMP280 init failed!");
    while (1);
  }

  // HX711 init
  scale.begin(DOUT, CLK);
  scale.set_scale(calibration_factor);
  scale.tare();

  // Connect to WiFi
  connectWiFi();

  // LoRa init
  SPI.begin(LORA_SCK, LORA_MISO, LORA_MOSI, LORA_SS);
  LoRa.setPins(LORA_SS, LORA_RST, LORA_DIO0);
  if (!LoRa.begin(433E6)) {
    Serial.println("LoRa init failed");
    while (1);
  }
  LoRa.setSyncWord(0xF1);
  Serial.println("LoRa Initialized");
}

void loop() {
  // Ensure WiFi is connected
  connectWiFi();

  // Read sensors
  temperature = bmp.readTemperature();
  pressure = bmp.readPressure() / 100.0F;
  altitude = bmp.readAltitude(1013.25);
  weight = scale.get_units(10);

  // Show on LCD
  lcd.clear();
  lcd.setCursor(0, 0);
  lcd.print("T:"); lcd.print(temperature, 1);
  lcd.print(" P:"); lcd.print(pressure, 0);
  lcd.setCursor(0, 1);
  lcd.print("W:"); lcd.print(weight);
  lcd.print(" A:"); lcd.print(altitude, 0);

  // Serial debug
  Serial.printf("T: %.2f C\n", temperature);
  Serial.printf("P: %.2f hPa\n", pressure);
  Serial.printf("A: %.2f m\n", altitude);
  Serial.printf("W: %ld\n", weight);

  // Send to LoRa
  String loRaData = String("T:") + temperature + 
                    " P:" + pressure + 
                    " A:" + altitude + 
                    " W:" + weight;
  Serial.println("Preparing LoRa send...");
LoRa.beginPacket();
LoRa.print(loRaData);
Serial.println("LoRa data prepared");
LoRa.endPacket(true); // async send
Serial.println("Sent via LoRa");


  // Upload to ThingSpeak
  Serial.println("Preparing ThingSpeak upload...");
if (WiFi.status() == WL_CONNECTED) {
    WiFiClientSecure client;
    client.setInsecure(); // Ignore SSL certificate

    HTTPClient http;
    String url = String(server) + "?api_key=" + apiKey +
                 "&field1=" + String(altitude) +
                 "&field2=" + String(temperature) +
                 "&field3=" + String(pressure) +
                 "&field4=" + String(weight);

    Serial.println("ThingSpeak URL: " + url);

    if (http.begin(client, url)) {
        Serial.println("HTTP connection started...");
        int httpCode = http.GET();
        if (httpCode > 0) {
            String payload = http.getString();
            Serial.println("ThingSpeak HTTP code: " + String(httpCode));
            Serial.println("ThingSpeak Response: " + payload);
        } else {
            Serial.println("ThingSpeak Error: " + http.errorToString(httpCode));
        }
        http.end();
    } else {
        Serial.println("Unable to connect to ThingSpeak (http.begin failed)");
    }
} else {
    Serial.println("WiFi not connected — skipping ThingSpeak upload.");
}


  delay(20000); // 20 sec delay for ThingSpeak
}
