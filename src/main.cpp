/**
By Peter LaMantia

Built using: 
  Arduino Websockets - https://github.com/gilmaimon/ArduinoWebsockets/
  Fortinet ThreatMap - https://threatmap.fortiguard.com/
  FastLED - https://github.com/FastLED/FastLED
  U8g2 - https://github.com/olikraus/u8g2
  ArduinoJson - https://arduinojson.org/
*/


#include <Arduino.h>
#include <WiFi.h>
#include <ArduinoWebsockets.h>
#include <FastLED.h>
#include <U8g2lib.h>
#include <Wire.h>
#include <ArduinoJson.h>

#include <secrets.h>


// display setup
U8X8_SSD1306_128X64_NONAME_HW_I2C u8x8(/* clock=*/ SCL, /* data=*/ SDA, /* reset=*/ U8X8_PIN_NONE);   // OLEDs without Reset of the Display
U8X8LOG u8x8log;
#define U8LOG_WIDTH 16
#define U8LOG_HEIGHT 8
uint8_t u8log_buffer[U8LOG_WIDTH*U8LOG_HEIGHT];

// websockets config
const char* websockets_server = "ws://threatmap.fortiguard.com:80/ws";  //server adress and port
const char* init_msg_1 = "[1,\"threatmap\",{\"roles\":{\"caller\":{\"features\":{\"caller_identification\":true,\"progressive_call_results\":true}},\"callee\":{\"features\":{\"caller_identification\":true,\"pattern_based_registration\":true,\"shared_registration\":true,\"progressive_call_results\":true,\"registration_revocation\":true}},\"publisher\":{\"features\":{\"publisher_identification\":true,\"subscriber_blackwhite_listing\":true,\"publisher_exclusion\":true}},\"subscriber\":{\"features\":{\"publisher_identification\":true,\"pattern_based_subscription\":true,\"subscription_revocation\":true}}}}]";
const char* init_msg_2 = "[32,8256555849692380,{},\"ips\"]";
using namespace websockets;
WebsocketsClient client;

JsonDocument doc;


void onMessageCallback(WebsocketsMessage message) {
  Serial.print("Got Message: ");
  Serial.println(message.data());

  // attempt JSON deserialization
  deserializeJson(doc, message.data());
  const char* threat = doc[4][0]["type"];
  Serial.println("Deserialized JSON: ");
  Serial.println(threat);

  // get src and dest countrycode
  const char* src_country = doc[4][0]["src"]["countrycode"];
  const char* dst_country = doc[4][0]["dst"]["countrycode"];

  // get severity
  const char* severity = doc[4][0]["severity"];

  // print the threat
  u8x8log.setRedrawMode(0);		// 0: Update screen with newline, 1: Update screen for every char
  u8x8log.print("\f");
  u8x8log.print("Source: ");
  u8x8log.print(src_country);
  u8x8log.print("\n");
  u8x8log.print("Dest:   ");
  u8x8log.print(dst_country);
  u8x8log.print("\n\n");
  u8x8log.print("Severity: \n ");
  u8x8log.print(severity);
  u8x8log.print("\n\n");
  delay(500);

  u8x8log.print("Threat: ");
  u8x8log.setRedrawMode(1);		// 0: Update screen with newline, 1: Update screen for every char
  u8x8log.print(threat);
  u8x8log.print("\n");
  delay(1500);
}


void onEventsCallback(WebsocketsEvent event, String data) {
  if (event == WebsocketsEvent::ConnectionOpened) {
    Serial.println("Connnection Opened");
  } else if (event == WebsocketsEvent::ConnectionClosed) {
    Serial.println("Connnection Closed");
  } else if (event == WebsocketsEvent::GotPing) {
    Serial.println("Got a Ping!");
  } else if (event == WebsocketsEvent::GotPong) {
    Serial.println("Got a Pong!");
  }
}


void setup() {
  pinMode(LED_BUILTIN, OUTPUT);
  digitalWrite(LED_BUILTIN, HIGH); // set LED off (high is off on XIAO ESP32-S3)

  // set up display
  u8x8.begin();
  u8x8.setFont(u8x8_font_victoriamedium8_r);
  u8x8log.begin(u8x8, U8LOG_WIDTH, U8LOG_HEIGHT, u8log_buffer);
  u8x8log.setRedrawMode(1);		// 0: Update screen with newline, 1: Update screen for every char
  u8x8log.print("Starting up...");

  // wait a moment before beginning serial
  // delay(2000);
  // Serial.begin(115200);
  // Serial.print("\nStarting up...");

  // Connect to wifi
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

  // Wait some time to connect to WiFi
  for (int i = 0; i < 10 && WiFi.status() != WL_CONNECTED; i++) {
    Serial.print(".");
    u8x8log.print(".");
    delay(1000);
  }
  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("\n\nERROR: Failed to connect to WiFi.");
    u8x8log.println("\n\nERROR: Failed to connect to WiFi.");
    digitalWrite(LED_BUILTIN, LOW); // set led ON for error
    while (true) {} // wait forever
  }
  Serial.print("\n\nWiFi connected.\n\n");
  u8x8log.print("\n\nWiFi connected.\n\n");

  // Setup Callbacks
  client.onMessage(onMessageCallback);
  client.onEvent(onEventsCallback);

  // add header
  client.addHeader("Sec-WebSocket-Protocol", "wamp.2.json");

  // Connect to server
  if (client.connect(websockets_server)) {
    // initial setup to begin receiving messages
    client.send(init_msg_1);
    client.send(init_msg_2);
  }
  else {
    Serial.println("ERROR: Failed to connect to WebSocket server.");
    u8x8log.println("ERROR: Failed to connect to WebSocket server.");
    digitalWrite(LED_BUILTIN, LOW); // set led ON for error
    while (true) {} // wait forever
  }  
}


void loop() {
  client.poll();
}
