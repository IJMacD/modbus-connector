#ifndef MODBUS_H
#define MODBUS_H

#include <netinet/in.h>

#define MODBUS_PROTOCOL_MODBUS 0
#define MODBUS_HEADER_LEN 7

struct modbus_adu {
    uint16_t transaction;
    uint16_t protocol;
    uint16_t length;
    uint8_t unit;
    uint8_t data[];
};

#endif