CC = gcc
CFLAGS = -Wall -Wextra -g -std=c11 -fsanitize=address -g
LDFLAGS = -pthread -fsanitize=address

SERV_DIR = src/server
CLIENT_DIR = src/client
BIN_DIR = bin