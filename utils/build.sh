#!/bin/bash
clear
make
valgrind --leak-check=full ./chatd `/labs/tsam15/my_port` & 

