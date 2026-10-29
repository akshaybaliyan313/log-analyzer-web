CC     ?= gcc
CFLAGS  = -O2 -Wall -Wextra

ifeq ($(OS),Windows_NT)
  EXE   = .exe
  LIBS  = -lws2_32
else
  EXE   =
  LIBS  = -lpthread
endif

all: server$(EXE) analyzer$(EXE)

server$(EXE): server.c analyzer_core.h
	$(CC) $(CFLAGS) -o $@ server.c $(LIBS)

analyzer$(EXE): analyzer.c analyzer_core.h
	$(CC) $(CFLAGS) -o $@ analyzer.c

clean:
	rm -f server server.exe analyzer analyzer.exe
