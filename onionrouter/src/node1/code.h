#ifndef CODE_H
#define CODE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <jansson.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <errno.h>
#include <ctype.h>
#include <signal.h>
#include <math.h>
#include <time.h>

// Константы
#define MAX_CLIENTS 1000
#define MAX_REQUESTS_PER_SECOND 100
#define BAN_TIME 60
#define PORT 8081
#define FORWARD_PORT 8082 
#define FORWARD_IP "127.0.0.1" 
#define BUFFER_SIZE 1024
#define MAX_PASSWORD_LEN 256
#define THRESHOLD 5
#define INITIAL_RATE_LIMIT 10.0
#define MAX_LEGIT_RATE 50.0
#define ALPHA 0.2

// Структуры
struct dnnsec_entry {
    char domain[100];
    char ip[16];
    unsigned char *signature;
    size_t sig_len;
};

typedef struct {
    char ip[INET_ADDRSTRLEN];
    int count;
    time_t last_request;
    time_t last_update;
    double request_rate;
    time_t banned_until;
    int is_banned;
} ClientInfo;

typedef struct {
    char data[BUFFER_SIZE];
    size_t len;
} Packet;

typedef struct {
    unsigned char data[256];
    size_t size;
} EncryptedPacket;

// Глобальные переменные (extern для доступа из других файлов)
extern Packet packet_buffer[THRESHOLD];
extern size_t packet_count;
extern ClientInfo clients[MAX_CLIENTS];
extern pthread_mutex_t lock;
extern volatile sig_atomic_t running;

// Прототипы функций
ClientInfo* find_or_create_client(const char *ip);
void update_rate(ClientInfo *client);
int check_rate_limiting(ClientInfo *client);
void handle_signal(int sig);
int authenticate(const char *password, const char *ip);
void* check_connections(void* arg);
void log_request(const char* ip);
int is_banned(const char* ip);
int forward_data(int client_socket, const char* buffer, size_t buffer_len);
void handle_client(int client_socket, const char* client_ip);

#endif 