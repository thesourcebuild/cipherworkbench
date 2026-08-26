#!/bin/sh
# Serves this folder and opens the app. See start.bat for why a static export cannot
# simply be opened from the filesystem.
cd "$(dirname "$0")"
PORT=8000

if command -v python3 >/dev/null 2>&1; then
    PY=python3
elif command -v python >/dev/null 2>&1; then
    PY=python
else
    echo "No Python found on PATH."
    echo "Serve this folder with any static file server, then open http://localhost:$PORT/"
    exit 1
fi

echo "Starting a local server on port $PORT ..."
"$PY" -m http.server "$PORT" &
SERVER_PID=$!
sleep 1

if command -v open >/dev/null 2>&1; then
    open "http://localhost:$PORT/"
elif command -v xdg-open >/dev/null 2>&1; then
    xdg-open "http://localhost:$PORT/"
else
    echo "Open http://localhost:$PORT/ in your browser."
fi

echo "Server running (pid $SERVER_PID). Press Ctrl+C to stop."
wait "$SERVER_PID"
