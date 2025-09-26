CC = gcc
CFLAGS = -Wall -Iinclude
SRC = src/main.c src/capture.c src/parser.c
OBJ = $(SRC:.c=.o)
TARGET = pcapture   # final binary name

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)

clean:
	rm -f src/*.o $(TARGET)

run: $(TARGET)
	sudo ./$(TARGET)