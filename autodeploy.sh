#!/bin/bash

./deploy.sh
while inotifywait -e modify -r src; do
    ./deploy.sh
done
