#!/bin/bash
g++ -Wformat -pedantic -O2 -maes -std=c++11 crypt_speed.cpp       -o crypt_speed

./crypt_speed