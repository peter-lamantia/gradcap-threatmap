# Graduation Cap Live Threat Map PCB

A project to learn more about microcontroller development and PCB design.

My plan is to: 
1. Reverse engineer the Fortinet WebSocket API
2. Program an ESP32 to connect to said API and log messages to serial
3. Design a PCB with:
   - an ESP32-S3
   - a world map graphic and WS2812B LEDs placed at key cities
   - a lithium battery and charging circuit
   - dimensions that will place it neatly on a graduation cap
   - a display to show the name of the attack (stretch goal)
4. Program the ESP32 to parse the incoming WebSocket such that:
   - the longitudinal data will map to the closest physical LED on the board
   - the LED will light up with a certain color depending on the threat type
   - ideally, I can make the LEDs animated in a cool way

So far, I've succeeded at 1 and 2. The beast will be designing the PCB, because that is totally new to me.

