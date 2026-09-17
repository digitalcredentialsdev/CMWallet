CXX ?= g++
CC ?= gcc
CXXFLAGS ?= -std=c++17 -Wall -Wextra -g -I. -I/usr/include/doctest -I/usr/include/nlohmann
CFLAGS ?= -Wall -Wextra -g -I. -Wno-unused-variable -Wno-unused-but-set-variable -Wno-format-overflow

# Common objects
COMMON_OBJS = dcql.o openid4vp1_0.o base64.o cJSON/cJSON.o issuance/provision.o

# Tests
test_runner: test_runner.o dcql.o openid4vp1_0.o base64.o cJSON/cJSON.o
	$(CXX) $(CXXFLAGS) -o $@ $^

test: test_runner
	./test_runner

# PNV tests
PNV_OBJS = pnv/dcql.o pnv/openid4vp1_0.o base64.o cJSON/cJSON.o

pnv_test: pnv/test/openid4vp1_0_test.o pnv/test/common.o $(PNV_OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^

pnv/test/openid4vp1_0_test.o: pnv/test/openid4vp1_0_test.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

pnv/test/common.o: pnv/test/common.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

pnv/dcql.o: pnv/dcql.c
	$(CC) $(CFLAGS) -c $< -o $@

pnv/openid4vp1_0.o: pnv/openid4vp1_0.c
	$(CC) $(CFLAGS) -c $< -o $@

test_pnv: pnv_test
	./pnv_test

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
	rm -f *.o cJSON/*.o issuance/*.o pnv/*.o pnv/test/*.o test_runner pnv_test

.PHONY: test test_pnv clean
