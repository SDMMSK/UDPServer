RM = rm -f
APP_NAME = udpserver

all: udpserver

udpserver: udpserver.cpp json11.cpp
	@g++ -o $(APP_NAME) $(APP_NAME).cpp -std=c++11 json11.cpp -pthread -s -O2

clean:
	@$(RM) *.o forwarder $(APP_NAME)
