CC := clang
CFLAGS := -g -O0 -Wno-int-to-void-pointer-cast -Wno-void-pointer-to-int-cast
LDFLAGS := -lmf

BIN_NAME := kanaya

SRC_DIR := ./src
BIN_DIR := ./bin

SRCS := $(shell find $(SRC_DIR) -name '*.c')
OBJS := $(SRCS:%.c=%.o)


all: $(BIN_DIR)/$(BIN_NAME)

$(BIN_DIR)/$(BIN_NAME): $(OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)

$(OBJ_DIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

.PHONY: clean
clean:
	rm -f $(BIN_DIR)/$(BIN_NAME) $(OBJS)
	rmdir $(BIN_DIR)
