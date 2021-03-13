CC = gcc
CFLAGS = -Wall -pedantic -g
BIN_DIR = bin

modbus-server:
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) -o $(BIN_DIR)/modbus-server modbus-server.c

modbus-client:
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) -o $(BIN_DIR)/modbus-client modbus-client.c

all: modbus-server modbus-client