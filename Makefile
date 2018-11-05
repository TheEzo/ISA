# Makefile
# Author: Tomas Willaschek 
# Login: xwilla00
# Project: ISA - dns export

PROJ=dns-export
SRC=dns-export.cpp
LIB=-lpcap

default:
	g++ ${SRC} -o ${PROJ} ${LIB}

