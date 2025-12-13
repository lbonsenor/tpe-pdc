include Makefile.inc

all: $(CLIENT_BIN) $(SERVER_BIN)

# Create dirs
$(BUILD_DIR)/client $(BUILD_DIR)/server $(BIN_DIR):
	mkdir -p $@

# Compile client lib objs
$(BUILD_DIR)/client/%.o: $(CLIENT_LIB)/%.c | $(BUILD_DIR)/client
	$(CC) $(CFLAGS) -I$(CLIENT_INCLUDE) -c $< -o $@

# Compile client main
$(CLIENT_MAIN_OBJ): $(CLIENT_MAIN) | $(BUILD_DIR)/client
	$(CC) $(CFLAGS) -I$(CLIENT_INCLUDE) -c $< -o $@

# Link client executable
$(CLIENT_BIN): $(CLIENT_OBJECTS) $(CLIENT_MAIN_OBJ) | $(BIN_DIR)
	$(CC) $(CLIENT_OBJECTS) $(CLIENT_MAIN_OBJ) $(LDFLAGS) -o $@

# Compile server library objects
$(BUILD_DIR)/server/%.o: $(SERVER_LIB)/%.c | $(BUILD_DIR)/server
	$(CC) $(CFLAGS) -I$(SERVER_INCLUDE) -c $< -o $@

# Compile server main
$(SERVER_MAIN_OBJ): $(SERVER_MAIN) | $(BUILD_DIR)/server
	$(CC) $(CFLAGS) -I$(SERVER_INCLUDE) -c $< -o $@

# Link server executable
$(SERVER_BIN): $(SERVER_OBJECTS) $(SERVER_MAIN_OBJ) | $(BIN_DIR)
	$(CC) $(SERVER_OBJECTS) $(SERVER_MAIN_OBJ) $(LDFLAGS) -o $@

# Build only client
client: $(CLIENT_BIN)

# Build only server
server: $(SERVER_BIN)

# Run client
run-client: $(CLIENT_BIN)
	./$(CLIENT_BIN)

# Run server
run-server: $(SERVER_BIN)
	./$(SERVER_BIN)

clean:
	rm -rf $(BIN_DIR) $(OBJ_DIR)

rebuild: clean all

help:
	@echo "Available targets:"
	@echo "  all          - Build both client and server (default)"
	@echo "  client       - Build only client"
	@echo "  server       - Build only server"
	@echo "  run-client   - Build and run client"
	@echo "  run-server   - Build and run server"
	@echo "  clean        - Remove build artifacts"
	@echo "  rebuild      - Clean and rebuild everything"
	@echo "  help         - Show this help message"

.PHONY: all client server run-client run-server clean rebuild help