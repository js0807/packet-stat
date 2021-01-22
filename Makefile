packet-stat	:	packet-stat.o
	g++ -o packet-stat packet-stat.o -lpcap
packet-stat.o	:	packet-stat.cpp
	g++ -c -o packet-stat.o packet-stat.cpp -lpcap
clean	:
	rm packet-stat.o packet-stat
