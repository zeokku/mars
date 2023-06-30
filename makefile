build:
# source should go before libs, otherwise they are skipped
# -L/usr/local/lib64/
# -std=c++2a for string.endsWith
	g++ -std=c++2a main.cpp -pthread -L/usr/local/lib64/ -lcrypto -o mars

release:
# https://stackoverflow.com/a/21250906/14776286
# statically link libs + remove unused symbols
	g++ -std=c++2a -O3 -fdata-sections -ffunction-sections main.cpp -pthread -static -L/usr/local/lib64/ -lcrypto -lz -ldl -o mars -Wl,--gc-sections -Wl,--strip-all

test:
	g++ test.cpp -pthread -L/usr/local/lib64/ -lcrypto -o test-suite && ./test-suite