#!/bin/bash

readonly disconnected_port=51111

for i in $(seq 1 $1 ) ; do
    wget http://127.0.0.1:"${disconnected_port}" &> /dev/null
done
