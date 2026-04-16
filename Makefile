CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2
LDFLAGS = -lcrypto

TARGET = encryptPawCLI
SRC = encryptPawCLI.cpp

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)

clean:
	rm -f $(TARGET)

.PHONY: clean
