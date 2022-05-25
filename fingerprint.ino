#include <Adafruit_Fingerprint.h>
#include <SPI.h>
#include <Ethernet.h>

#define HMAC_HEADER_NAME "HMAC: "

SoftwareSerial serial(2, 3);
Adafruit_Fingerprint sensor = Adafruit_Fingerprint(&serial, 0);
EthernetServer server(80);
EthernetClient client;

uint64_t command_counter = 0;

// Maintain ethernet connection and log errors
void maintainEthernet()
{
	switch (Ethernet.maintain()) {
	case 1:
		Serial.println(F("Error: renewed fail"));
		break;
	case 2:
		Serial.println(F("Renewed success"));
		break;
	case 3:
		Serial.println(F("Error: rebind fail"));
		break;
	case 4:
		Serial.println(F("Rebind success"));
		break;
	default:
		break;
	}
}

// Attempt to read an HMAC header from the client
bool try_read_hmac_header(uint8_t *buffer)
{
	if (!client.find(HMAC_HEADER_NAME)) return false;

	char octet[3] = {0};
	for (int i=0; i<32; i++) {
		int first = client.read();
		if (first < 0 || first == '\n') return false;
		int second = client.read();
		if (second < 0 || second == '\n') return false;

		octet[0] = first;
		octet[1] = second;
		*buffer = strtol(octet, 0, 10);
		buffer++;
	}

	return true;
}

bool handle_command_request(String *cmd)
{
	client = server.available();
	if (!client) return false;

	uint8_t hmac_buffer[32];
	if (!try_read_hmac_header(hmac_buffer)) return false;

	// Skip remaining headers
	client.find("\r\n\r\n");

	int bytes_read = 0;
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

	Serial.println(F("starting fingerprint sensor..."));
	sensor.begin(57600);
	delay(5);

	if (sensor.verifyPassword()) {
		Serial.println(F("found fingerprint sensor"));
	} else {
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

	sensor.LEDcontrol(FINGERPRINT_LED_ON, 0, FINGERPRINT_LED_RED, 0);

	sensor.getTemplateCount();

	if (sensor.templateCount != 0)  {
		Serial.println("waiting for valid finger...");
		Serial.print("sensor contains "); Serial.print(sensor.templateCount); Serial.println(" templates");
	}
}

void loop()
{
	maintainEthernet();

	client = server.available();
	if (client) {
		Serial.println(client.read());
	}
}
