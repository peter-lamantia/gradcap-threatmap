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


typedef struct {
  double latitude;
  double longitude;
} Location;

Location cities[] = {
  {49.2827, -123.1207}, // Vancouver
  {41.8781, -87.6298},  // Chicago
  {43.6511, -79.3837},  // Toronto
  {40.7128, -74.0060},  // New York
  {25.7617, -80.1918},  // Miami
  {29.7604, -95.3698},  // Houston
  {34.0522, -118.2437}, // Los Angeles
  {19.4326, -99.1332},  // Mexico City
  {4.7110, -74.0721},   // Bogota
  {-12.0464, -77.0428}, // Lima
  {-33.4489, -70.6693}, // Santiago
  {-34.6037, -58.3816}, // Buenos Aires
  {-23.5505, -46.6333}, // Sao Paulo
  {-33.9249, 18.4241},  // Cape Town
  {-26.2041, 28.0473},  // Johannesburg
  {-1.2921, 36.8219},   // Nairobi
  {15.5007, 32.5599},   // Khartoum
  {30.0444, 31.2357},   // Cairo
  {40.4168, -3.7038},   // Madrid
  {48.8566, 2.3522},    // Paris
  {51.5074, -0.1278},   // London
  {55.7558, 37.6173},   // Moscow
  {41.0082, 28.9784},   // Istanbul
  {35.6892, 51.3890},   // Tehran
  {24.7136, 46.6753},   // Riyadh
  {24.8607, 67.0011},   // Karachi
  {28.6139, 77.2090},   // Delhi
  {19.0760, 72.8777},   // Mumbai
  {23.8103, 90.4125},   // Dhaka
  {29.5630, 106.5516},  // Chongqing
  {39.9042, 116.4074},  // Beijing
  {37.5665, 126.9780},  // Seoul
  {35.6762, 139.6503},  // Tokyo
  {31.2304, 121.4737},  // Shanghai
  {22.3193, 114.1694},  // Hong Kong
  {14.5995, 120.9842},  // Manila
  {10.8231, 106.6297},  // Ho Chi Minh City
  {13.7563, 100.5018},  // Bangkok
  {3.1390, 101.6869},   // Kuala Lumpur
  {-6.2088, 106.8456},  // Jakarta
  {-33.8688, 151.2093}  // Sydney
};

// display setup
// U8X8_SSD1306_128X64_NONAME_HW_I2C u8x8(/* clock=*/ SCL, /* data=*/ SDA, /* reset=*/ U8X8_PIN_NONE);   // OLEDs without Reset of the Display
// U8X8LOG u8x8log;
// #define U8LOG_WIDTH 16
// #define U8LOG_HEIGHT 8
// uint8_t u8log_buffer[U8LOG_WIDTH*U8LOG_HEIGHT];

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

  // // print the threat
  // u8x8log.setRedrawMode(0);		// 0: Update screen with newline, 1: Update screen for every char
  // u8x8log.print("\f");
  // u8x8log.print("Source: ");
  // u8x8log.print(src_country);
  // u8x8log.print("\n");
  // u8x8log.print("Dest:   ");
  // u8x8log.print(dst_country);
  // u8x8log.print("\n\n");
  // u8x8log.print("Severity: \n ");
  // u8x8log.print(severity);
  // u8x8log.print("\n\n");
  // delay(500);

  // u8x8log.print("Threat: ");
  // u8x8log.setRedrawMode(1);		// 0: Update screen with newline, 1: Update screen for every char
  // u8x8log.print(threat);
  // u8x8log.print("\n");
  // delay(1500);
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
  // u8x8.begin();
  // u8x8.setFont(u8x8_font_victoriamedium8_r);
  // u8x8log.begin(u8x8, U8LOG_WIDTH, U8LOG_HEIGHT, u8log_buffer);
  // u8x8log.setRedrawMode(1);		// 0: Update screen with newline, 1: Update screen for every char
  // u8x8log.print("Starting up...");

  // wait a moment before beginning serial
  delay(2000);
  Serial.begin(115200);
  // Serial.print("\nStarting up...");

  // Connect to wifi
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

  // Wait some time to connect to WiFi
  for (int i = 0; i < 10 && WiFi.status() != WL_CONNECTED; i++) {
    Serial.print(".");
    // u8x8log.print(".");
    delay(1000);
  }
  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("\n\nERROR: Failed to connect to WiFi.");
    // u8x8log.println("\n\nERROR: Failed to connect to WiFi.");
    digitalWrite(LED_BUILTIN, LOW); // set led ON for error
    while (true) {} // wait forever
  }
  Serial.print("\n\nWiFi connected.\n\n");
  // u8x8log.print("\n\nWiFi connected.\n\n");

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
    // u8x8log.println("ERROR: Failed to connect to WebSocket server.");
    digitalWrite(LED_BUILTIN, LOW); // set led ON for error
    Serial.end();
    while (true) {} // wait forever
  }  
}


void loop() {
  client.poll();
}
