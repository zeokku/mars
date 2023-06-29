OPENSSL_PATH=/home/ceo/src/openssl

build:
# source should go before libs, otherwise they are skipped
# -L/usr/local/lib64/
	g++ main.cpp -pthread -L/usr/local/lib64/ -lcrypto -o main

test:
	g++ test.cpp -pthread -L/usr/local/lib64/ -lcrypto -o test-suite && ./test-suite