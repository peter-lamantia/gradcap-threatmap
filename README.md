# Graduation Cap Live Threat Map PCB

## About

This is a pet project to learn more about microcontroller development and PCB design.

My plan is to: 
1. Reverse engineer the Fortinet WebSocket API
2. Program an ESP32 to connect to said API and log messages to serial
3. Design a PCB with:
   - an ESP32-S3
   - a world map graphic and WS2812B LEDs placed at key cities
   - a lithium battery and charging circuit
   - dimensions that will place it neatly on a graduation cap
   - a display to show the attack details
4. Program the ESP32 to parse the incoming WebSocket such that:
   - the longitudinal data will map to the closest physical LED on the board
   - the LED will light up with a certain color depending on the threat type
   - ideally, I can make the LEDs animated in a cool way


## Roadmap
- WiFi connection reestablishment
- WebSocket connection reestablishment
- An actual PCB to mess around with. It may be useful to do this in revisions, e.g. make a PCB with the LEDs first, write the software for that, then make a more capable PCB with all components. After all, it is my first time doing this.
- Figure out how to actually debug (not just print program state to serial!)


## Changelog

### 2024-07-07
- Full migration to Platform.io (it's great!)
- Started printing out threats to an OLED display
   - Used the U8g2 library, specifically [u8log](https://github.com/olikraus/u8g2/wiki/u8logreference) for display output
   - Parsed the JSON sent from the WebSocket using [ArduinoJSON](https://arduinojson.org/)
- Added and did some testing with [FastLED](https://github.com/FastLED/FastLED), but have not implemented it yet (it is likely best to wait until I've made the PCB)

### 2024-06-29 (initial commit)
- WiFi connection establishment
- WebSocket connection to Fortinet
- Prints WebSocket messages to serial


## Known issues/fixes
- If serial is enabled, the XIAO ESP32-S3 will not allow reflashing. To fix this, hold the boot button while powering it on, and then flash at will!
