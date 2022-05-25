# [R503 Fingerprint Sensor](https://www.adafruit.com/product/4651) based lock for [lockbot](https://github.com/zeusWPI/lockbot)

## Hardware

 - Arduino UNO
 - Ethernet shield
 - R503 Fingerprint Sensor

## Building

1. Install the [ethernet](https://www.arduino.cc/reference/en/libraries/ethernet/) and [adafruit fingerprint](https://github.com/adafruit/Adafruit-Fingerprint-Sensor-Library) libraries
2. Edit `secrets.h` to contain the correct values
3. Upload the sketch

## R503 Pinout

Number | Color  | Name   | Function
-------|--------|--------|---------
1      | red    | Vcc    | Power, 3V3
2      | black  | GND    | Ground
3      | yellow | TXD    | Serial TX
4      | green  | RXD    | Serial RX
5      | blue   | WAKEUP | Finger detection signal
6      | white  | 3V3    | Touch induction power (?)
