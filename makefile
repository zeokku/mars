OPENSSL_PATH=/home/ceo/src/openssl

build:
# source should go before libs, otherwise they are skipped
# -L/usr/local/lib64/
# -std=c++2a for string.endsWith
	g++ main.cpp -std=c++2a -pthread -L/usr/local/lib64/ -lcrypto -o mars

test:
	g++ test.cpp -pthread -L/usr/local/lib64/ -lcrypto -o test-suite && ./test-suite