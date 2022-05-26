# [R503 Fingerprint Sensor](https://www.adafruit.com/product/4651) based lock for [lockbot](https://github.com/zeusWPI/lockbot)

## Usage

All requests require a valid HMAC signature of the request body to be sent
under an `HMAC: {HMAC}` HTTP header.

See `client.py` for reference on how requests work.

### **Enrolling a new fingerprint**

Send a request with a body of the following format
```
{time};enroll;{ID};
```
where `{time}` is the time the message was sent (in unix seconds) and `{ID}` is
the requested ID of the new fingerprint.

**Note:** If the supplied ID was already in use its data will be overwritten,
use the `list` command to see which IDs are available.

Once this command is received the sensor will go into 'enroll' mode, signified
by the LED turning blue with a slow breathing effect. \
To start, place your finger on the sensor until the LED quickly flashes purple,
remove your finger and place it on the sensor again after it has gone back to
pulsating blue. \
Once the sensor quickly flashes blue your fingerprint is registered.

This command will always return an HTTP/200 OK reply as it simply switches the
behaviour of the program, errors with the enrollment process itself will need
to be read via the serial port.

### **Deleting a fingerprint**

Send a request with a body of the following format
```
{time};delete;{ID};
```
where `{time}` is the time the message was sent (in unix seconds) and `{ID}` is
the ID of the fingerprint to delete.

**Note:** This function can succeed regardless of whether or not the requested
ID actually contains a fingerprint, an error will only be returned if the
sensor itself throws an error.

This command will return either an HTTP/200 OK response if all went well, or
an HTTP/500 Internal Server Error response with a message in the body if an
error occured.

### **Listing all used IDs**

Send a request with a body of the following format
```
{time};list;
```
where `{time}` is the time the message was sent (in unix seconds).

This command will return an HTTP/200 OK response with a string in the body
encoding the state of all 200 possible IDs; a 0 indicated the ID at that
index is unused, a 1 indicates that it is used.

## Callbacks

### Body too long
### Missing HMAC
### Invalid HMAC

### Fingerprint detected

POST {mattermore_url}/fingerprint/{ID}/detect

### Fingerprint enrolled

POST {mattermore_url}/fingerprint/{ID}

### Fingerprint deleted

DELETE {mattermore_url}/fingerprint/{ID}

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
