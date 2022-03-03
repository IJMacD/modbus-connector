#include "modbus.h"

void print_bytes (uint8_t *buf, size_t len);

void read_tcp_message (int sockfd, struct modbus_adu **msg);

void send_tcp_message (int sockfd, struct modbus_adu *msg);

void read_serial_message (int serial_fd, struct modbus_adu **msg);

void send_serial_message (int serial_fd, struct modbus_adu *msg);

