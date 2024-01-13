make:
	gcc sniffer.c -o sniffer -lpcap
clean:
	rm -r sniffer
