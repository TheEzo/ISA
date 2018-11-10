# Makefile
# Author: Tomas Willaschek 
# Login: xwilla00
# Project: ISA - dns export

ARCHIVE=xwilla00.tgz
PROJ=dns-export
SRC=dns-export.cpp
MORE=Makefile
LIB=-lpcap

default:
	g++ ${SRC} -o ${PROJ} ${LIB}

pack:
	tar -cvf ${ARCHIVE} ${MORE} ${SRC}

merlin:
	scp ${ARCHIVE} xwilla00@merlin:~/ISA/${ARCHIVE}
	ssh xwilla00@merlin
