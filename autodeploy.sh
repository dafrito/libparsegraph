#!/bin/bash

deploy() {
    make && make check && make install
}

deploy
while inotifywait -e modify -r src; do
    deploy
done
