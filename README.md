# [R503 Fingerprint Sensor](https://www.adafruit.com/product/4651) based lock for [lockbot](https://github.com/zeusWPI/lockbot)

## Hardware

 - Arduino UNO
 - Ethernet shield
 - R503 Fingerprint Sensor

## Building

 1. Install the [ethernet](https://www.arduino.cc/reference/en/libraries/ethernet/) and [adafruit fingerprint](https://github.com/adafruit/Adafruit-Fingerprint-Sensor-Library) libraries
 2. Edit `secrets.h` to contain the correct values
 3. Upload the sketch

## Commands

 - "{time};enroll;{ID};" - Enroll a new fingerprint with id {ID} \
   This will put the sensor into a loop where it waits for a finger to be
   detected. Once it finds one it will enroll it with the given id and send
   the image to {mattermore_url}/fingerprint/image/{id}
 - "{time};delete;{ID};" - Delete the fingerprint with id {ID}
 - "{time};list;" - List all used ids

## Responses

 - POST {mattermore_url}/fingerprint/detect/{id} - Fingerprint with id {ID} was
 detected, if id = 0 the fingerprint was unknown.

## R503 Pinout

Number | Color  | Name   | Function
-------|--------|--------|---------
1      | red    | Vcc    | Power, 3V3
2      | black  | GND    | Ground
3      | yellow | TXD    | Serial TX
4      | green  | RXD    | Serial RX
5      | blue   | WAKEUP | Finger detection signal
6      | white  | 3V3    | Touch induction power (?)
