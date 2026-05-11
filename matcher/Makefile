CXX = g++
CC = gcc
CXXFLAGS = -std=c++17 -Wall -Wextra -g -I. -I/usr/include/doctest -I/usr/include/nlohmann
CFLAGS = -Wall -Wextra -g -I. -Wno-unused-variable -Wno-unused-but-set-variable -Wno-format-overflow

# Common objects
COMMON_OBJS = dcql.o openid4vp1_0.o base64.o cJSON/cJSON.o issuance/provision.o

# Tests
test_runner: test_runner.o dcql.o openid4vp1_0.o base64.o cJSON/cJSON.o
	$(CXX) $(CXXFLAGS) -o $@ $^

test: test_runner
	./test_runner

test_runner.o: test_runner.cc
	$(CXX) $(CXXFLAGS) -c $< -o $@

dcql.o: dcql.c
	$(CC) $(CFLAGS) -c $< -o $@

openid4vp1_0.o: openid4vp1_0.c
	$(CC) $(CFLAGS) -c $< -o $@

base64.o: base64.c
	$(CC) $(CFLAGS) -c $< -o $@

cJSON/cJSON.o: cJSON/cJSON.c
	$(CC) $(CFLAGS) -c $< -o $@

issuance/provision.o: issuance/provision.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o cJSON/*.o issuance/*.o test_runner

.PHONY: test clean
