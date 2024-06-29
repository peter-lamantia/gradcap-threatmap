/**
By Peter LaMantia

Built using: 
  Arduino Websockets - https://github.com/gilmaimon/ArduinoWebsockets/
  Fortinet ThreatMap - https://threatmap.fortiguard.com/
*/


#include <ArduinoWebsockets.h>
#include <WiFi.h>
#include <passwords.h>

const char* websockets_server = "ws://threatmap.fortiguard.com:80/ws";  //server adress and port
const char* init_msg_1 = "[1,\"threatmap\",{\"roles\":{\"caller\":{\"features\":{\"caller_identification\":true,\"progressive_call_results\":true}},\"callee\":{\"features\":{\"caller_identification\":true,\"pattern_based_registration\":true,\"shared_registration\":true,\"progressive_call_results\":true,\"registration_revocation\":true}},\"publisher\":{\"features\":{\"publisher_identification\":true,\"subscriber_blackwhite_listing\":true,\"publisher_exclusion\":true}},\"subscriber\":{\"features\":{\"publisher_identification\":true,\"pattern_based_subscription\":true,\"subscription_revocation\":true}}}}]";
const char* init_msg_2 = "[32,8256555849692380,{},\"ips\"]";

using namespace websockets;

void onMessageCallback(WebsocketsMessage message) {
  Serial.print("Got Message: ");
  Serial.println(message.data());
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

WebsocketsClient client;
void setup() {
  pinMode(LED_BUILTIN, OUTPUT);

  Serial.begin(115200);
  Serial.print("\nStarting up.");

  // Connect to wifi
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

  // Wait some time to connect to wifi
  for (int i = 0; i < 10 && WiFi.status() != WL_CONNECTED; i++) {
    Serial.print(".");
    delay(1000);
  }
  Serial.println("\nConnected to WiFi.");

  // Setup Callbacks
  client.onMessage(onMessageCallback);
  client.onEvent(onEventsCallback);
  Serial.println("Callbacks set up.");

  // add a header
  client.addHeader("Sec-WebSocket-Protocol", "wamp.2.json");

  // Connect to server
  client.connect(websockets_server);

  // initial setup to begin receiving messages
  Serial.println("Sending init_msg_1.");
  client.send(init_msg_1);
  Serial.println("init_msg_1 sent.");
  Serial.println("Sending init_msg_2.");
  client.send(init_msg_2);
  Serial.println("init_msg_2 sent.");
}

void loop() {
  client.poll();
}
