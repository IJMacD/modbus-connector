CC = gcc
CFLAGS = -Wall -pedantic -g -O3
BIN_DIR := bin

.PHONY: all prep clean

all: modbus-server modbus-client

prep:
	@mkdir -p $(BIN_DIR)

$(BIN_DIR)/send_receive.o: send_receive.c
	$(CC) -c $^ $(CFLAGS) -o $@

$(BIN_DIR)/serial.o: serial.c
	$(CC) -c $^ $(CFLAGS) -o $@

$(BIN_DIR)/modbus-server.o: modbus-server.c
	$(CC) -c $^ $(CFLAGS) -o $@

$(BIN_DIR)/modbus-client.o: modbus-client.c
	$(CC) -c $^ $(CCFLAGS) -o $@

modbus-server: prep $(BIN_DIR)/modbus-server.o $(BIN_DIR)/send_receive.o $(BIN_DIR)/serial.o
	$(CC) -o $(BIN_DIR)/modbus-server $(BIN_DIR)/modbus-server.o $(BIN_DIR)/send_receive.o $(BIN_DIR)/serial.o

modbus-client: prep $(BIN_DIR)/modbus-client.o $(BIN_DIR)/send_receive.o $(BIN_DIR)/serial.o
	$(CC) -o $(BIN_DIR)/modbus-client $(BIN_DIR)/modbus-client.o $(BIN_DIR)/send_receive.o $(BIN_DIR)/serial.o

clean:
	rm -f $(BIN_DIR)/*
