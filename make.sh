#!/bin/bash
g++ -Wformat -pedantic -O2 -msse -msse2 -msse4 -maes -std=c++11 crypt_speed.cpp       -o crypt_speed

./crypt_speed