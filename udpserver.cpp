/* g++ -o udpserver udpserver.cpp -std=c++11 json11.cpp -pthread -s -O2 */
/* udpserver 127.0.0.1 10003 */

#include <iostream>
#include <sstream>
#include <cstring>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>
#include <thread>

#include "json11.hpp"

using namespace std;
using namespace json11;

unsigned int key[4] = {0xECA5, 0xE52E, 0xEE00, 0xCE5B};

#define BLOCK_SIZE 8

int sockfd;
int StopFlag = 1;

void error(char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

void printLog(string msg);
void printLog(string severity, string msg);
void termHandler(int i);
void threadProc(int tnum);

// XTea Encryption, use if necessary...
void xteaEncipher(unsigned int num_rounds, uint32_t v[2], uint32_t const key[4]);
void xteaDecipher(unsigned int num_rounds, uint32_t v[2], uint32_t const key[4]);
void stringCrypt(char *inout, int len, bool encrypt);

void printLog(string msg) {
    printLog("INFO", msg);
}

void printLog(string severity, string msg) {
    if (severity == "") {
        severity = "INFO";
    }

    char buff[20];
    struct tm *sTm;

    time_t now = time(0);

    sTm = gmtime(&now);

    strftime(buff, sizeof(buff), "%Y-%m-%dT%H:%M:%S", sTm);

    Json my_json = Json::object {
        { "msg", msg },
        { "severity", severity },
        { "time", buff }
    };
    string json_obj_str = my_json.dump();
    cout << json_obj_str << "\n";
}

int main(int argc, char **argv) {
    struct sigaction sa;
    sigset_t newset;

    sigemptyset(&newset);
    sigaddset(&newset, SIGHUP);
    sigprocmask(SIG_BLOCK, &newset, 0);
    sa.sa_handler = termHandler;
    sigaction(SIGTERM, &sa, 0);

    unsigned int nthreads = thread::hardware_concurrency();
    stringstream ss;
    ss << nthreads;
    printLog("Hardware concurrency (CPU)... " + ss.str());

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in server;

    if (argc >= 3) {
        char *host = argv[1];
        int port = atoi(argv[2]);

        // UDP Server
        server.sin_family = AF_INET;
        server.sin_port = htons(port);
        server.sin_addr.s_addr = inet_addr(host);

        printLog("INFO", "Binding server to socket... OK");

        if (bind(sockfd, (struct sockaddr *)&server, sizeof(server)) < 0) {
            perror(NULL);
            close(sockfd);
            exit(0);
        }

        vector<thread> threads(nthreads);

        for (int i = 0; i < nthreads; i++) {
            stringstream ss;
            ss << i;
            printLog("INFO", "Start thread...  " + ss.str());
            thread thr(threadProc, i);
            threads[i] = move(thr);
        }

        while (StopFlag) {
            sleep(1);
        }

        for (auto& thr : threads) {
            thr.join();
        }

        exit(EXIT_SUCCESS);
    } else {
        cout << "udpserver <host> <port>" << endl;
    }
}

void threadProc(int tnum) {
    struct sockaddr_in client;

    stringstream ss;

    ss << tnum;
    string tnumStr = ss.str();
    printLog("INFO", "Server thread " + tnumStr + " started... OK");

    while (StopFlag) {
        char buffer[1024] = {};
        socklen_t cs = sizeof(client);
        printLog("INFO", "Waiting for a UDP datagram (" + tnumStr + ")...");
        int rc = recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *)&client, &cs);
        printLog("INFO", "Received (" + tnumStr + ")");

        if (rc < 0) {
            printLog("ERROR", "ERROR READING FROM SOCKET (" + tnumStr + ")!");
        } else {
            for (int i = 0; i < rc; i++) {
                printf("0x%x;", buffer[i]);
            }

            cout << endl;
            unsigned char *conbuf = (unsigned char *)buffer;
        }
    }
}

void termHandler(int i) {
    printLog("INFO", "Server shutdown...");
    StopFlag = 0;
    sleep(10);
    printLog("INFO", "Server stopped... OK");

    exit(EXIT_SUCCESS);
}

// XTea Encryption, use if necessary...
void xteaEncipher(unsigned int num_rounds, uint32_t v[2], uint32_t const key[4]) {
    unsigned int i;
    uint32_t v0 = v[0], v1 = v[1], sum = 0, delta = 0x9E3779B9;
    for (i = 0; i < num_rounds; i++) {
        v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
        sum += delta;
        v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3]);
    }
    v[0] = v0; v[1] = v1;
}

void xteaDecipher(unsigned int num_rounds, uint32_t v[2], uint32_t const key[4]) {
    unsigned int i;
    uint32_t v0 = v[0], v1 = v[1], delta = 0x9E3779B9, sum = delta * num_rounds;
    for (i = 0; i < num_rounds; i++) {
        v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3]);
        sum -= delta;
        v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
    }
    v[0] = v0; v[1] = v1;
}

void stringCrypt(char *inout, int len, bool encrypt) // encrypt true - encrypt, false - decript
{
    for (int i = 0; i < len / BLOCK_SIZE; i++) {
        if (encrypt) {
            xteaEncipher(32, (uint32_t*)(inout + (i * BLOCK_SIZE)), key);
        } else {
            xteaDecipher(32, (uint32_t*)(inout + (i * BLOCK_SIZE)), key);
        }
    }
    if (len % BLOCK_SIZE != 0) {
        int mod = len % BLOCK_SIZE;
        int offset = (len / BLOCK_SIZE) * BLOCK_SIZE;
        char data[BLOCK_SIZE];
        memcpy(data, inout + offset, mod);

        if (encrypt) {
            xteaEncipher(32, (uint32_t*)data, key);
        } else {
            xteaDecipher(32, (uint32_t*)data, key);
        }
        memcpy(inout + offset, data, mod);
    }
}