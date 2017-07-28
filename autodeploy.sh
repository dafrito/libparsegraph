#!/bin/bash
while true; do
    ./deploy.sh
    inotifywait -e modify -r src doc/*.html --format '%w %e' | read file event;
done
