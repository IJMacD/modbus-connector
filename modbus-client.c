#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <time.h>

#include <arpa/inet.h>

#define PORT "502"

#include "send_receive.h"

#ifndef DEBUG
#define DEBUG 0
#endif

#define MAXDATASIZE 100 // max number of bytes we can get at once

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET)
    {
        return &(((struct sockaddr_in *)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6 *)sa)->sin6_addr);
}

void get_value(int sockfd, char *type, int address)
{
    size_t data_size = 5;
    struct modbus_adu *msg = malloc(MODBUS_HEADER_LEN + data_size);

    msg->transaction = 1000;
    msg->protocol = MODBUS_PROTOCOL_MODBUS;
    msg->length = data_size + 1;
    msg->unit = 1;

    uint8_t function;

    if (address > 0xFFFF)
    {
        fprintf(stderr, "address out of range: %d\n", address);
        exit(1);
    }

    if (strcmp(type, "auto") == 0)
    {
        if (address < 0x2000)
        {
            // Read Coil
            function = 0x01;
        }
        else if (address < 0x3000)
        {
            // Read Discrete Input
            function = 0x02;
        }
        else if (address < 0x4000)
        {
            // Read Input Register
            function = 0x04;
        }
        else if (address >= 0x9000)
        {
            // Read Holding Register
            function = 0x03;
        }
        else
        {
            fprintf(stderr, "cannot determine correct function\n");
            exit(1);
        }
    }
    else if (strcmp(type, "coil") == 0)
    {
        function = 0x01;
    }
    else if (strcmp(type, "holding") == 0)
    {
        function = 0x03;
    }
    else if (strcmp(type, "input") == 0)
    {
        function = 0x04;
    }
    else
    {
        fprintf(stderr, "type must be: coil/input/holding\n");
        exit(1);
    }

    int quantity = 1;

    msg->data[0] = function;
    msg->data[1] = (address >> 8) & 0xff;
    msg->data[2] = address & 0xff;
    msg->data[3] = (quantity >> 8) & 0xff;
    msg->data[4] = quantity & 0xff;

    send_tcp_message(sockfd, msg);

    if (DEBUG)
    {
        printf("client: sent message\n");
    }

    read_tcp_message(sockfd, &msg);

    function = msg->data[0];

    if (function & 0x80)
    {
        printf("device %d: error %d\n", msg->unit, msg->data[1]);
    }
    else if (function == 1)
    {
        // uint8_t byte_count = msg->data[1];
        int value = msg->data[2];
        printf("Value: %d\n", value);
    }
    else if (function <= 4)
    {
        // uint8_t byte_count = msg->data[1];
        int value = (msg->data[2] << 8) | msg->data[3];
        printf("Value: %d\n", value);
    }
    else if (function <= 6)
    {
        int address = (msg->data[1] << 8) | msg->data[2];
        int value = (msg->data[3] << 8) | msg->data[4];
        printf("Address: %02X Value: %d\n", address, value);
    }
    else
    {
        printf("client: other function response %d\n", function);
    }
}

void set_value(int sockfd, char *type, int address, int value)
{
    size_t data_size = 5;
    struct modbus_adu *msg = malloc(MODBUS_HEADER_LEN + data_size);

    msg->transaction = 1000;
    msg->protocol = MODBUS_PROTOCOL_MODBUS;
    msg->length = data_size + 1;
    msg->unit = 1;

    uint8_t function;

    if (address > 0xFFFF)
    {
        fprintf(stderr, "address out of range: %d\n", address);
        exit(1);
    }

    if (strcmp(type, "auto") == 0)
    {
        if (address < 0x2000)
        {
            // Write Single Coil
            function = 0x05;

            // Value must be on or off
            if (value)
            {
                value = 0xFF00;
            }
        }
        else if (address < 0x3000)
        {
            // Discrete Input
            fprintf(stderr, "Cannot write to discrete input\n");
            exit(1);
        }
        else if (address < 0x4000)
        {
            // Input Register
            fprintf(stderr, "Cannot write to input register\n");
            exit(1);
        }
        else if (address >= 0x9000)
        {
            // Write Holding Register
            function = 0x06;
        }
        else
        {
            fprintf(stderr, "cannot determine correct function\n");
            exit(1);
        }
    }
    else if (strcmp(type, "coil") == 0)
    {
        function = 0x05;

        if (value != 0xff00 && value != 0x0000)
        {
            fprintf(stderr, "status must be: on/off\n");
            exit(1);
        }
    }
    else if (
        strcmp(type, "register") == 0 ||
        strcmp(type, "holding") == 0)
    {
        function = 0x06;

        if (value > 0xFFFF)
        {
            fprintf(stderr, "value out of range: %d\n", value);
            exit(1);
        }
    }
    else
    {
        fprintf(stderr, "type must be: coil/register\n");
        exit(1);
    }

    msg->data[0] = function;
    msg->data[1] = (address >> 8) & 0xff;
    msg->data[2] = address & 0xff;
    msg->data[3] = (value >> 8) & 0xff;
    msg->data[4] = value & 0xff;

    send_tcp_message(sockfd, msg);

    if (DEBUG)
    {
        printf("client: sent message\n");
    }

    read_tcp_message(sockfd, &msg);

    if (msg->data[0] & 0x80)
    {
        printf("error setting value\n");
    }
    else
    {
        printf("OK\n");
    }
}

void set_values(int sockfd, char *type, int start_address, uint16_t *values, int value_count)
{
    size_t data_size = 6 + value_count * 2;
    struct modbus_adu *msg = malloc(MODBUS_HEADER_LEN + data_size - 1);

    msg->transaction = 1000;
    msg->protocol = MODBUS_PROTOCOL_MODBUS;
    msg->length = data_size + 1;
    msg->unit = 1;

    uint8_t function;

    if (start_address > 0xFFFF)
    {
        fprintf(stderr, "address out of range: %d\n", start_address);
        exit(1);
    }

    if (strcmp(type, "coil") == 0)
    {
        function = 0x0F;

        fprintf(stderr, "not implemented: write multiple coils\n");
        exit(1);
    }
    else if (strcmp(type, "register") == 0 || strcmp(type, "holding") == 0)
    {
        function = 0x10;

        for (int i = 0; i < value_count; i++)
        {
            msg->data[6 + (i * 2)] = (values[i] >> 8) & 0xff;
            msg->data[6 + (i * 2) + 1] = values[i] & 0xff;
        }
    }
    else
    {
        fprintf(stderr, "type must be: coil/register\n");
        exit(1);
    }

    msg->data[0] = function;
    msg->data[1] = (start_address >> 8) & 0xff;
    msg->data[2] = start_address & 0xff;
    msg->data[3] = (value_count >> 8) & 0xff;
    msg->data[4] = value_count & 0xff;
    msg->data[5] = value_count * 2;

    send_tcp_message(sockfd, msg);

    if (DEBUG)
    {
        printf("client: sent message\n");
    }

    read_tcp_message(sockfd, &msg);

    if (msg->data[0] & 0x80)
    {
        printf("error setting value\n");
    }
    else
    {
        printf("OK\n");
    }
}

void set_time(int sockfd)
{
    printf("Setting time to ");

    time_t now;
    time(&now);
    struct tm *info;
    info = localtime(&now);

    printf("%04d-%02d-%02dT%02d:%02d:%02d\n", info->tm_year + 1900, info->tm_mon + 1, info->tm_mday, info->tm_hour, info->tm_min, info->tm_sec);

    uint16_t registers[3];

    registers[0] = (info->tm_min << 8) | info->tm_sec;
    registers[1] = (info->tm_mday << 8) | info->tm_hour;
    registers[2] = ((info->tm_year - 100) << 8) | (info->tm_mon + 1);

    // printf("Registers: %d %d %d\n", registers[0], registers[1], registers[2]);

    set_values(sockfd, "holding", 0x9013, registers, 3);
}

void print_usage(char *argv0)
{
    // fprintf(stderr,"usage:\t%1$s <hostname> <type> <address> [<value>]\n\t%1$s <hostname> <type> <address> <...values>\n\t%1$s <hostname> time\n", argv0);
    // fprintf(stderr,
    //     "usage:\n"
    //     "\t%1$s <hostname> <type> 0x<address> [<value>]\n"
    //     "\t%1$s <hostname> <type> 0x<address> <...values>\n"
    //     "\t%1$s <hostname> time\n"
    //     "<type> = coil|input|holding|auto\n",
    // argv0);
    fprintf(stderr,
            "usage:\n"
            "\t%1$s <hostname> 0x<address> [<value>]\n"
            "\t%1$s <hostname> 0x<address> <...values>\n"
            "\t%1$s <hostname> time\n",
            argv0);
}

int main(int argc, char *argv[])
{
    int sockfd;
    struct addrinfo hints, *servinfo, *p;
    int rv;
    char s[INET6_ADDRSTRLEN];

    if (argc < 3)
    {
        print_usage(argv[0]);
        exit(1);
    }

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    char *hostname = argv[1];

    if ((rv = getaddrinfo(hostname, PORT, &hints, &servinfo)) != 0)
    {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }

    // loop through all the results and connect to the first we can
    for (p = servinfo; p != NULL; p = p->ai_next)
    {
        if ((sockfd = socket(p->ai_family, p->ai_socktype,
                             p->ai_protocol)) == -1)
        {
            perror("client: socket");
            continue;
        }

        if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1)
        {
            close(sockfd);
            perror("client: connect");
            continue;
        }

        break;
    }

    if (p == NULL)
    {
        fprintf(stderr, "client: failed to connect\n");
        return 2;
    }

    inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr),
              s, sizeof s);
    if (DEBUG)
    {
        printf("client: connecting to %s\n", s);
    }

    freeaddrinfo(servinfo); // all done with this structure

    // e.g. modbus-client <hostname> time
    if (argc == 3 && strcmp("time", argv[2]) == 0)
    {
        set_time(sockfd);
        return 0;
    }

    // Assumes hexidecimal register address. Supports optional '0x' prefix
    // e.g.
    //  modbus-client <hostname> 3100
    //  modbus-client <hostname> 0x3100
    uint16_t address = strtol(argv[2], NULL, 16);

    // Read value
    if (argc == 3)
    {
        get_value(sockfd, "auto", address);
    }
    // Write value
    else if (argc == 4)
    {
        uint16_t value;

        // shortcut for coils on/off
        if (strcmp(argv[3], "on") == 0)
        {
            value = 0xFF00;
        }
        else if (strcmp(argv[3], "off") == 0)
        {
            value = 0x0000;
        }
        else
        {
            value = atoi(argv[3]);
        }

        set_value(sockfd, "auto", address, value);
    }
    // Set multiple values
    else
    {
        int value_count = argc - 3;
        uint16_t *values = malloc(2 * value_count);

        for (int i = 0; i < value_count; i++)
        {
            char *arg = argv[i + 3];
            if (strcmp(arg, "on") == 0)
            {
                values[i] = 0xFF00;
            }
            else if (strcmp(arg, "off") == 0)
            {
                values[i] = 0x0000;
            }
            else
            {
                values[i] = atoi(arg);
            }
        }

        set_values(sockfd, "auto", address, values, value_count);
    }

    close(sockfd);

    return 0;
}
