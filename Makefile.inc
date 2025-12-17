CC = gcc
CFLAGS = -Wall -Wextra -g -std=c11 -fsanitize=address -g
LDFLAGS = -pthread -fsanitize=address

SRC_DIR = src
BIN_DIR = bin
BUILD_DIR = build
SERVER_DIR = $(SRC_DIR)/server
CLIENT_DIR = $(SRC_DIR)/client

# Client paths
CLIENT_INCLUDE = $(CLIENT_DIR)/include
CLIENT_LIB = $(CLIENT_DIR)/lib
CLIENT_MAIN = $(CLIENT_DIR)/main.c

# Server paths
SERVER_INCLUDE = $(SERVER_DIR)/include
SERVER_LIB = $(SERVER_DIR)/lib
SERVER_MAIN = $(SERVER_DIR)/main.c

# Server source files - EXCLUDE test files
SERVER_SOURCES = $(filter-out %_test.c, $(wildcard $(SERVER_LIB)/*.c))
SERVER_OBJECTS = $(patsubst $(SERVER_LIB)/%.c,$(BUILD_DIR)/server/%.o,$(SERVER_SOURCES))
SERVER_MAIN_OBJ = $(BUILD_DIR)/server/main.o

# Client source files - EXCLUDE test files  
CLIENT_SOURCES = $(filter-out %_test.c, $(wildcard $(CLIENT_LIB)/*.c))
CLIENT_OBJECTS = $(patsubst $(CLIENT_LIB)/%.c,$(BUILD_DIR)/client/%.o,$(CLIENT_SOURCES))
CLIENT_MAIN_OBJ = $(BUILD_DIR)/client/main.o

# Output executables
CLIENT_BIN = $(BIN_DIR)/client
SERVER_BIN = $(BIN_DIR)/server