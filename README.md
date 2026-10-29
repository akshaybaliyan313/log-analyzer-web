# Intelligent Log Analyzer

A log analyzer written in C, with a browser-based frontend.

Paste log text (or load a file) and get instant statistics: total characters,
alphabets, digits, special characters, whitespace, and a chart of the most
frequent characters.

## How it works

Browser (index.html) → POST /api/analyze → C server (server.c) → analyze() → JSON

- `analyzer_core.h` – shared counting logic
- `analyzer.c` – command-line version
- `server.c` – HTTP backend (Windows and Linux/macOS)
- `public/index.html` – frontend

## Build and run

Windows (MinGW):

    gcc -O2 -o server server.c -lws2_32
    .\server.exe 8080

Linux / macOS:

    gcc -O2 -o server server.c -lpthread
    ./server 8080

Then open http://127.0.0.1:8080
