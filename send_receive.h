#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>

#include "crc.h"
#include "serial.h"
#include "modbus.h"

#ifndef DEBUG
#define DEBUG 0
#endif

void print_bytes (uint8_t *buf, size_t len) {
    for (int i = 0; i < len; i++) {
        printf("%02X ", buf[i]);
    }
    printf("\n");
}

void read_tcp_message (int sockfd, struct modbus_adu **msg) {
    (*msg) = (struct modbus_adu *)malloc(MODBUS_HEADER_LEN);
    uint8_t buf[MODBUS_HEADER_LEN];

    int numbytes = recv(sockfd, buf, MODBUS_HEADER_LEN, 0);

    if (numbytes == -1) {
        perror("recv");
        exit(1);
    }

    if (numbytes == 0) {
        if (DEBUG) {
            printf("disconnected\n");
        }
        exit(0);
    }

    if (numbytes < MODBUS_HEADER_LEN) {
        fprintf(stderr, "Didn't receive a whole packet\n");
        exit(1);
    }

    if (DEBUG) {
        printf("Received a message!\n");

        print_bytes(buf, MODBUS_HEADER_LEN);
    }

    (*msg)->transaction = (buf[0] << 8) | buf[1];
    (*msg)->protocol = (buf[2] << 8) | buf[3];
    (*msg)->length = (buf[4] << 8) | buf[5];
    (*msg)->unit = buf[6];

    void *tmp = realloc((*msg), MODBUS_HEADER_LEN + (*msg)->length - 1);
    if (tmp == NULL) {
        fprintf(stderr, "Realloc failed\n");
        exit(1);
    }
    (*msg) = (struct modbus_adu *)tmp;

    if (DEBUG) {
        printf("Transaction ID: %d\n", (*msg)->transaction);
        if ((*msg)->protocol == MODBUS_PROTOCOL_MODBUS) {
            printf("Protocol: MODBUS\n");
        } else {
            printf("Protocol: UNKNOWN\n");
        }
        printf("Length: %d\n", (*msg)->length);
        printf("Unit ID: %d\n", (*msg)->unit);
    }

    numbytes = recv(sockfd, (*msg)->data, (*msg)->length - 1, 0);

    if (numbytes == -1) {
        perror("recv");
        exit(1);
    }

    if (numbytes < (*msg)->length - 1) {
        fprintf(stderr, "only read %d bytes\n", numbytes);
        return;
    }

    if (DEBUG) {
        printf("Data: ");
        print_bytes((*msg)->data, (*msg)->length - 1);
    }
}

void send_tcp_message (int sockfd, struct modbus_adu *msg) {
    uint8_t *buf = (uint8_t *)malloc(MODBUS_HEADER_LEN + msg->length - 1);

    buf[0] = (msg->transaction >> 8) & 0xff;
    buf[1] = msg->transaction & 0xff;
    buf[2] = (msg->protocol >> 8) & 0xff;
    buf[3] = msg->protocol & 0xff;
    buf[4] = (msg->length >> 8) & 0xff;
    buf[5] = msg->length & 0xff;

    memcpy(buf + 6, &msg->unit, msg->length);

    if (DEBUG) {
        print_bytes(buf, MODBUS_HEADER_LEN + msg->length - 1);
    }

    if (send(sockfd, buf, MODBUS_HEADER_LEN + msg->length - 1, 0) == -1) {
        perror("send");
    }
}

void read_serial_message (int serial_fd, struct modbus_adu **msg) {
    unsigned char buf[8];
    size_t out_count;
    size_t read_count;

    read_count = read(serial_fd, buf, 2);

    if (read_count != 2) {
        printf("No response from device\n");
        exit(1);
    }

    int unit = buf[0];
    int function = buf[1];

    if (function & 0x80) {
        read(serial_fd, buf + 2, 1);

        printf("device %d: error %d\n", unit, buf[2]);

        out_count = 3;
    }
    else if (unit != (*msg)->unit) {
        printf("device ID doesn't match\n");

        // Indicate gateway error
        buf[1] = (*msg)->data[0] | 0x80;
        buf[2] = 0x0B;
        out_count = 3;
    }
    else if (function != (*msg)->data[0]) {
        printf("function mis-match, expected: %d received: %d\n", (*msg)->data[0], function);

        if (DEBUG) {
            print_bytes(buf, 2);
        }

        // Indicate gateway error
        buf[1] = (*msg)->data[0] | 0x80;
        buf[2] = 0x0B;
        out_count = 3;
    } else if (function <= 4) {
        read(serial_fd, buf + 2, 1);
        uint8_t byte_count = buf[2];

        read_count = read(serial_fd, buf + 3, byte_count);

        if (read_count != byte_count) {
            printf("server: unable to read enough data");
        }
        else if (DEBUG) {
            printf("OK Response: ");
            print_bytes(buf, read_count + 3);
        }

        out_count = read_count + 3;
    } else if (function <= 6 || function == 0x10) {
        read_count = read(serial_fd, buf + 2, 4);

        if (read_count != 4) {
            printf("server: unable to read enough data");
        }
        else if (DEBUG) {
            printf("OK Response: ");
            print_bytes(buf, read_count + 2);
        }

        out_count = read_count + 2;
    } else {
        printf("server: other function response %d\n", function);
    }

    if (out_count > (*msg)->length) {
        void *tmp = realloc((*msg), MODBUS_HEADER_LEN + out_count - 1);
        if (tmp == NULL) {
            fprintf(stderr, "Can't allocate memory\n");
            exit(1);
        }
        (*msg) = (struct modbus_adu *)tmp;
    }

    (*msg)->length = out_count;

    memcpy(&((*msg)->unit), buf, out_count);
}

void send_serial_message (int serial_fd, struct modbus_adu *msg) {
    uint8_t *buf = (uint8_t *)malloc(msg->length + 2);

    memcpy(buf, &msg->unit, msg->length);

    unsigned short crc = CRC16(buf, msg->length);

    buf[msg->length + 1] = (crc >> 8) & 0xff;
    buf[msg->length] = crc & 0xff;

    // CRC is wrong way round?
    // buf[msg->length] = (crc >> 8) & 0xff;
    // buf[msg->length + 1] = crc & 0xff;

    if (DEBUG) {
        printf("Sending serial message\n");
        print_bytes(buf, msg->length + 2);
    }

    if (serial_fd != -1) {
        write(serial_fd, buf, msg->length + 2);
    }

    free(buf);
}
