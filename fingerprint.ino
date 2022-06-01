#include <Adafruit_Fingerprint.h>
#include <SPI.h>
#include <Ethernet.h>

#include "./sha256/sha256.h"
#include "./sha256/sha256.cpp"
#include "./secrets.h"

#define HMAC_HEADER_NAME "HMAC: "
#define MESSAGE_BODY_SIZE 128 + 1 // + 1 for null byte
#define FINGERPRINT_LIB_SIZE 200

#define MATTERMORE_SERVER_HOST "mattermore.zeus.gent"
#define MATTERMORE_SERVER_PORT 80

#define SENSOR_TX 5
#define SENSOR_RX 6
#define SENSOR_INT 3

SoftwareSerial serial(SENSOR_TX, SENSOR_RX);
Adafruit_Fingerprint sensor = Adafruit_Fingerprint(&serial, 0);
EthernetServer server(80);
EthernetClient client;

// Whether or not the program is in enroll mode
volatile bool ENROLL_ENABLED = false;

// The timestamp sent with the previous request
//
// Used to prevent replay attacks
uint64_t previous_timestamp = 0;

// Maintain ethernet connection and log errors
void maintainEthernet()
{
	switch (Ethernet.maintain()) {
	case 1:
		Serial.println(F("ethernet renewal fail"));
		break;
	case 2:
		Serial.println(F("ethernet renewed"));
		break;
	case 3:
		Serial.println(F("ethernet rebind fail"));
		break;
	case 4:
		Serial.println(F("ethernet rebind success"));
		break;
	default:
		break;
	}
}

// Send an HTTP/400 Bad Request response and close the connection
void send_bad_request(const char *msg, int len)
{
	client.println(F("HTTP/1.1 400"));
	client.println(F("Connection: close"));
	client.print(F("Content-Length: "));
	client.println(len);
	client.println();
	client.print(msg);
	client.flush();
	client.stop();
}

// Send an HTTP/200 OK response
void send_ok(const char *msg, int len)
{
	client.println(F("HTTP/1.1 200"));
	client.print(F("Content-Length: "));
	client.println(len);
	client.println();
	client.println(msg);
	client.flush();
	client.stop();
}

// Send an HTTP/500 Internal Server Error response
void send_internal_error(const char *msg, int len)
{
	client.println(F("HTTP/1.1 500"));
	client.print(F("Content-Length: "));
	client.println(len);
	client.println();
	client.println(msg);
	client.flush();
	client.stop();
}

// Attempt to read an HMAC header from the client
bool try_read_hmac_header(uint8_t *buffer)
{
	if (!client.find(HMAC_HEADER_NAME)) return false;

	char octet[3] = {0};
	for (uint8_t i=0; i<32; i++) {
		// The HMAC header is hex encoded so two bytes must be read
		// to get a single actual byte
		int first = client.read();
		if (first < 0 || first == '\n') return false;
		int second = client.read();
		if (second < 0 || second == '\n') return false;

		octet[0] = (char)first;
		octet[1] = (char)second;
		*buffer = strtol(octet, 0, 16);
		buffer++;
	}

	return true;
}

// Put the LED in its standard mode of solid purple
void led_standard()
{
	sensor.LEDcontrol(FINGERPRINT_LED_ON, 0, FINGERPRINT_LED_PURPLE, 0);
}

// Flash the LED red for 1s to signify an error
void led_warning()
{
	sensor.LEDcontrol(FINGERPRINT_LED_FLASHING, 16, FINGERPRINT_LED_RED, 8);
	delay(1000);
}

// Breathe the LED blue infinitely to signify the program is in enroll mode
void led_enroll()
{
	sensor.LEDcontrol(FINGERPRINT_LED_BREATHING, 96, FINGERPRINT_LED_BLUE, 255);
}

// Call and return the result of sensor.getImage() while logging errors
uint8_t get_image_and_log()
{
	uint8_t result = sensor.getImage();
	switch (result) {
	case FINGERPRINT_OK:
	case FINGERPRINT_NOFINGER:
		break;
	case FINGERPRINT_PACKETRECIEVEERR:
		Serial.println(F("communication error"));
		goto show_warning;
	case FINGERPRINT_IMAGEFAIL:
		Serial.println(F("imaging error"));
		goto show_warning;
	default:
		Serial.println(F("unknown error"));
	show_warning:
		led_warning();
		break;
	}

	return result;
}

// Call and return the result of sensor.image2Tz(slot) while logging errors
uint8_t image2tz_and_log(uint8_t slot)
{
	uint8_t result = sensor.image2Tz(slot);
	switch (result) {
	case FINGERPRINT_OK:
		break;
	case FINGERPRINT_IMAGEMESS:
		Serial.println(F("image too messy"));
		goto show_warning;
	case FINGERPRINT_PACKETRECIEVEERR:
		Serial.println(F("communication error"));
		goto show_warning;
	case FINGERPRINT_FEATUREFAIL:
		Serial.println(F("could not read finger features"));
		goto show_warning;
	case FINGERPRINT_INVALIDIMAGE:
		Serial.println(F("invalid image"));
		goto show_warning;
	default:
		Serial.println(F("unknown error"));
	show_warning:
		led_warning();
		break;
	}

	return result;
}

// Enroll a new fingerprint
void try_enroll_fingerprint(uint8_t enroll_id)
{
	led_enroll();

	Serial.print(F("enrolling fingerprint #"));
	Serial.print(enroll_id);
	Serial.println(F("..."));

	Serial.println(F("waiting for first fingerprint..."));
	uint8_t result = -1;
	while (result != FINGERPRINT_OK) {
		result = get_image_and_log();
		if (!(result == FINGERPRINT_OK || result == FINGERPRINT_NOFINGER)) {
			led_enroll();
		}
	}

	Serial.println(F("creating first feature map..."));
	result = image2tz_and_log(1);
	if (result != FINGERPRINT_OK) {
		led_standard();
		return;
	}

	// Wait for user to remove their finger
	sensor.LEDcontrol(FINGERPRINT_LED_FLASHING, 16, FINGERPRINT_LED_PURPLE, 255);
	result = 0;
	while (result != FINGERPRINT_NOFINGER) {
		result = sensor.getImage();
	}
	led_enroll();

	Serial.println(F("waiting for second fingerprint..."));
	result = -1;
	while (result != FINGERPRINT_OK) {
		result = get_image_and_log();
		if (!(result == FINGERPRINT_OK || result == FINGERPRINT_NOFINGER)) {
			led_enroll();
		}
	}

	Serial.println(F("creating second feature map..."));
	result = image2tz_and_log(2);
	if (result != FINGERPRINT_OK) {
		led_standard();
		return;
	}

	Serial.println(F("creating model..."));
	result = sensor.createModel();
	switch (result) {
	case FINGERPRINT_OK:
		break;
	case FINGERPRINT_PACKETRECIEVEERR:
		Serial.println(F("communication error"));
		goto create_model_error;
	case FINGERPRINT_ENROLLMISMATCH:
		Serial.println(F("fingerprint mismatch"));
		goto create_model_error;
	default:
		Serial.println(F("unknown error"));
	create_model_error:
		led_warning();
		led_standard();
		return;
	}

	Serial.println(F("storing model..."));
	result = sensor.storeModel(enroll_id);
	switch (result) {
	case FINGERPRINT_OK:
		break;
	case FINGERPRINT_PACKETRECIEVEERR:
		Serial.println(F("communication error"));
		goto store_model_error;
	case FINGERPRINT_BADLOCATION:
		Serial.println(F("bad location"));
		goto store_model_error;
	case FINGERPRINT_FLASHERR:
		Serial.println(F("flash error"));
		goto store_model_error;
	default:
		Serial.println(F("unknown error"));
	store_model_error:
		led_warning();
		led_standard();
		return;
	}

	// TODO: add mattermore callback

	Serial.print(F("enrolled fingerprint #"));
	Serial.println(enroll_id);
	sensor.LEDcontrol(FINGERPRINT_LED_FLASHING, 16, FINGERPRINT_LED_BLUE, 8);
	delay(1000);

	led_standard();
}

// Attempt to recognize the fingerprint on the sensor
void try_recognize_fingerprint()
{
	Serial.println(F("finger detected, attempting to recognize..."));

	Serial.println(F("reading fingerprint..."));
	uint8_t result = -1;
	while (result != FINGERPRINT_OK) {
		result = get_image_and_log();
		led_standard();
	}

	// The delay(1000)s are used as a crude means of debouncing

	Serial.println(F("creating feature map..."));
	result = image2tz_and_log(1);
	if (result != FINGERPRINT_OK) {
		led_standard();
		delay(1000);
		return;
	}

	Serial.println(F("searching for template..."));
	uint8_t finger_id = 0;
	uint16_t confidence = 0;
	result = sensor.fingerSearch();
	switch (result) {
	case FINGERPRINT_OK:
		finger_id = sensor.fingerID;
		confidence = sensor.confidence;
		break;
	case FINGERPRINT_PACKETRECIEVEERR:
		Serial.println(F("communication error"));
		goto finger_search_error;
	case FINGERPRINT_NOTFOUND:
		Serial.println(F("detected unknown fingerprint"));
		goto finger_search_error;
	default:
		Serial.println(F("unknown error"));
	finger_search_error:
		led_warning();
		led_standard();
		delay(1000);
		return;
	}

	Serial.print(F("found fingerprint #"));
	Serial.println(finger_id);
	Serial.print(F("confidence: "));
	Serial.println(confidence);

	// TODO: add mattermore callback
	if (finger_id != 0) {
		sensor.LEDcontrol(FINGERPRINT_LED_FLASHING, 16, FINGERPRINT_LED_BLUE, 8);
		delay(1000);
		led_standard();
	}

	delay(1000);
}

// Delete a fingerprint given its id
void delete_fingerprint(uint8_t id)
{
	Serial.print(F("deleting fingerprint #"));
	Serial.print(id);
	Serial.println(F("..."));

	uint8_t result = sensor.deleteModel(id);
	switch (result) {
	case FINGERPRINT_OK:
		send_ok("", 0);
		Serial.print(F("deleted fingerprint #"));
		Serial.println(id);
		break;
	case FINGERPRINT_PACKETRECIEVEERR:
		send_internal_error("communication error", 20);
		Serial.println(F("communication error"));
		break;
	case FINGERPRINT_BADLOCATION:
		send_bad_request("invalid id", 11);
		Serial.println(F("bad location"));
		break;
	case FINGERPRINT_FLASHERR:
		send_internal_error("flash error", 12);
		Serial.println(F("flash error"));
		break;
	default:
		send_internal_error("unkown error", 13);
		Serial.println(F("unknown error"));
		break;
	}
}

// Get all the used ids in the internal buffer and send them as a string back
// to the client
void send_used_ids()
{
	char id_buffer[FINGERPRINT_LIB_SIZE + 1];
	uint8_t result;
	for (int i=0; i<FINGERPRINT_LIB_SIZE; i++) {
		result = sensor.loadModel(i);
		switch (result) {
		case FINGERPRINT_OK:
			id_buffer[i] = '1';
			break;
		default:
			id_buffer[i] = '0';
			break;
		}
	}
	id_buffer[FINGERPRINT_LIB_SIZE] = 0;

	send_ok(id_buffer, FINGERPRINT_LIB_SIZE);
}

void handle_message()
{
	client = server.available();
	if (!client) return;

	uint8_t hmac_buffer[32];
	if (!try_read_hmac_header(hmac_buffer)) {
		send_bad_request("missing HMAC", 13);
		// TODO: send mattermore request as warning
		return;
	}

	// Skip remaining headers
	client.find("\r\n\r\n");

	uint8_t body_idx = 0;
	uint8_t body_buffer[MESSAGE_BODY_SIZE];
	while (body_idx < MESSAGE_BODY_SIZE - 1 && client.available()) {
		body_buffer[body_idx] = client.read();
		body_idx++;
	}
	body_buffer[body_idx] = 0;

	if (client.available()) {
		send_bad_request("body too long", 14);
		// TODO: send mattermore request as warning
		return;
	}

	Sha256Class hmac_generator;
	hmac_generator.initHmac(DOWN_COMMAND_KEY, strlen((const char *)DOWN_COMMAND_KEY));
	hmac_generator.write(body_buffer, body_idx);
	uint8_t *hmac = hmac_generator.resultHmac();

	if (memcmp(hmac, hmac_buffer, 32) != 0) {
		send_bad_request("invalid HMAC", 13);
		// TODO: send mattermore request as warning
		return;
	}

	uint8_t chr;
	body_idx = 0; // Reuse body_idx to avoid allocating another variable

	uint64_t received_timestamp = 0;
	while ((chr = body_buffer[body_idx]) != ';') {
		// Timestamps must end with a ;
		if (chr == 0) {
			send_bad_request("malformed", 10);
			return;
		}

		received_timestamp *= 10;
		received_timestamp += chr - '0';
		body_idx++;
	}

	if (received_timestamp <= previous_timestamp) {
		send_bad_request("replay", 7);
		// TODO: send mattermore request to warn of replay
		return;
	}

	body_idx++; // Skip ;

	// 16 bytes should be enough for the command
	char command[16];
	uint8_t cmd_idx = 0;
	while ((chr = body_buffer[body_idx]) != ';') {
		// Commands must end with a ;
		if (chr == 0) {
			send_bad_request("malformed", 10);
			return;
		}

		command[cmd_idx] = chr;
		cmd_idx++;
		body_idx++;
	}
	command[cmd_idx] = 0;

	body_idx++; // Skip ;

	if (strcmp("enroll", command) == 0) {
		// An id cannot be longer than 3 digits + null byte
		char id[4];
		uint8_t id_idx = 0;
		while ((chr = body_buffer[body_idx]) != ';') {
			// Ids must end with a ;
			if (chr == 0) {
				send_bad_request("malformed", 10);
				return;
			}

			id[id_idx] = chr;
			id_idx++;
			body_idx++;
		}
		id[id_idx] = 0;

		// The id actually has to exist
		if (id_idx == 0) {
			send_bad_request("missing id", 11);
			return;
		}

		uint8_t parsed_id = atoi(id);

		if (parsed_id == 0 || parsed_id >= 200) {
			send_bad_request("invalid id", 11);
			return;
		}

		send_ok("", 0);

		ENROLL_ENABLED = true;
		try_enroll_fingerprint(parsed_id);
		ENROLL_ENABLED = false;
	} else if (strcmp("delete", command) == 0) {
		// An id cannot be longer than 3 digits + null byte
		char id[4];
		uint8_t id_idx = 0;
		while ((chr = body_buffer[body_idx]) != ';') {
			// Ids must end with a ;
			if (chr == 0) {
				send_bad_request("malformed", 10);
				return;
			}

			id[id_idx] = chr;
			id_idx++;
			body_idx++;
		}
		id[id_idx] = 0;

		// The id actually has to exist
		if (id_idx == 0) {
			send_bad_request("missing id", 11);
			return;
		}

		uint8_t parsed_id = atoi(id);

		if (parsed_id == 0 || parsed_id >= 200) {
			send_bad_request("invalid id", 11);
			return;
		}

		delete_fingerprint(parsed_id);
	} else if (strcmp("list", command) == 0) {
		send_used_ids();
	} else {
		send_bad_request("unknown command", 16);
		return;
	}

	// Once the command has been validated to be correct, update the global
	// timestamp tracker to prevent replays
	previous_timestamp = received_timestamp;

	return;
}

void setup()
{
	Serial.begin(115200);
	Serial.println(F("starting..."));

	Serial.println(F("initialising ethernet..."));
	byte MAC[] = { 0x00, 0x20, 0x91, 0x00, 0x00, 0x01 };
	byte IP[] = { 10, 0, 1, 14 };
	Ethernet.begin(MAC, IP);

	Serial.println(F("starting webserver..."));
	server.begin();

	Serial.println(F("Setting up pins..."));
	pinMode(SENSOR_INT, INPUT);

	Serial.println(F("starting fingerprint sensor..."));
	sensor.begin(57600);
	delay(5);

	if (!sensor.verifyPassword()) {
		Serial.println(F("fingerprint sensor not found or password was incorrect"));
		while (1) {
			delay(1);
		}
	}

	// Serial.println(F("reading sensor parameters..."));
	// sensor.getParameters();
	// Serial.print(F("status: 0x")); Serial.println(sensor.status_reg, HEX);
	// Serial.print(F("sys ID: 0x")); Serial.println(sensor.system_id, HEX);
	// Serial.print(F("capacity: ")); Serial.println(sensor.capacity);
	// Serial.print(F("security level: ")); Serial.println(sensor.security_level);
	// Serial.print(F("device address: ")); Serial.println(sensor.device_addr, HEX);
	// Serial.print(F("packet len: ")); Serial.println(sensor.packet_len);
	// Serial.print(F("baud rate: ")); Serial.println(sensor.baud_rate);

	Serial.println("started");
	led_standard();
}

void loop()
{
	maintainEthernet();

	handle_message();

	if (!(digitalRead(SENSOR_INT)) && !(ENROLL_ENABLED)) {
		try_recognize_fingerprint();
	}
}
