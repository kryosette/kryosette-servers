#include "code.h"

Packet packet_buffer[THRESHOLD];
size_t packet_count = 0;
ClientInfo clients[MAX_CLIENTS] = {0};
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
volatile sig_atomic_t running = 1;

ClientInfo* find_or_create_client(const char *ip) {
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (strcmp(clients[i].ip, ip) == 0) {
            return &clients[i];
        }
    }
    
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].count == 0) {
            strncpy(clients[i].ip, ip, INET_ADDRSTRLEN-1);
            clients[i].ip[INET_ADDRSTRLEN-1] = '\0';
            clients[i].count = 0;
            clients[i].last_update = time(NULL);
            return &clients[i];
        }
    }
    return NULL;
}

void secure_pad(unsigned char *data, size_t *current_len, size_t max_len, int mode) {
    size_t target_len;

    switch (mode) {
        case 0: //fixed size
            target_len = max_len;
            break;
        case 1: // random padding (50-100% of max_len)
            RAND_bytes((unsigned char *)&target_len, sizeof(target_len));
            target_len = *current_len + (target_len % (max_len - *current_len + 1));
            break; 
        case 2:
            target_len = max_len;
            const char *http_headers = "\r\nX-Padding: a1b2c3d4\r\n";
            size_t http_pad_len = strlen(http_headers);
            if (*current_len + http_pad_len <= max_len) {
                memcpy(data + *current_len, http_headers, http_pad_len);
                *current_len += http_pad_len;
            }
            return;
    }
    if (target_len <= *current_len) return;

    RAND_bytes(data + *current_len, target_len - *current_len);
    *current_len = target_len;
}

void handle_crypto_error(const char *msg) {
    fprintf(stderr, "Crypto error: %s\n", msg);
    exit(1);
}


void update_rate(ClientInfo *client) {
    time_t now = time(NULL);
    double elapsed = difftime(now, client->last_update);

    if (elapsed > 0) {
        double instant_rate = 1.0 / elapsed;
        client->request_rate = ALPHA * instant_rate + (1 - ALPHA) * client->request_rate;
    }
    
    client->last_update = now;
}

int check_rate_limiting(ClientInfo *client) {
    update_rate(client);

    double dynamic_limit = INITIAL_RATE_LIMIT;

    if (client->request_rate > dynamic_limit &&
        client->request_rate < MAX_LEGIT_RATE) {
        return 1;
    }

    return 0;
}

void handle_signal(int sig) {
    running = 0;
}

int authenticate(const char *password, const char *ip) {
    const char *correct_password = "secure_hashed_password";
    (void)ip;
    
    return strcmp(password, "password") == 0;
}

void* check_connections(void* arg) {
    while (running) {
        pthread_mutex_lock(&lock);
        time_t now = time(NULL);

        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (clients[i].is_banned && now < clients[i].banned_until) {
                continue;
            }

            if (clients[i].count > MAX_REQUESTS_PER_SECOND && 
                difftime(now, clients[i].last_request) <= 1) {
                clients[i].is_banned = 1;
                clients[i].banned_until = now + BAN_TIME;
                printf("IP %s banned for %d seconds\n", clients[i].ip, BAN_TIME);
            } else if (difftime(now, clients[i].last_request) > 1) {
                clients[i].count = 0;
                clients[i].is_banned = 0;
            }
        }

        pthread_mutex_unlock(&lock);
        sleep(1);
    }
    return NULL;
}

void log_request(const char* ip) {
    pthread_mutex_lock(&lock);
    time_t now = time(NULL);
    int found = 0;

    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (strcmp(clients[i].ip, ip) == 0) {
            clients[i].count++;
            clients[i].last_request = now;
            found = 1;
            break;
        }
    }

    if (!found) {
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (clients[i].count == 0) {
                strncpy(clients[i].ip, ip, INET_ADDRSTRLEN-1);
                clients[i].ip[INET_ADDRSTRLEN-1] = '\0';
                clients[i].count = 1; 
                clients[i].last_request = now;
                clients[i].banned_until = 0;
                clients[i].is_banned = 0;
                break;
            }
        }
    }
    pthread_mutex_unlock(&lock);
}

int is_banned(const char* ip) {
    pthread_mutex_lock(&lock);
    time_t now = time(NULL);
    int banned = 0;

    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (strcmp(clients[i].ip, ip) == 0) {
            if (clients[i].is_banned && now < clients[i].banned_until) {
                banned = 1;
            }
            break;
        }
    }

    pthread_mutex_unlock(&lock);
    return banned;
}

int forward_data(int client_socket, const char* buffer, size_t buffer_len) {
    struct sockaddr_in forward_addr;
    int forward_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (forward_sock < 0) {
        perror("Forward socket creation failed");
        return -1;
    }

    memset(&forward_addr, 0, sizeof(forward_addr));
    forward_addr.sin_family = AF_INET;
    forward_addr.sin_port = htons(FORWARD_PORT);

    if (inet_pton(AF_INET, FORWARD_IP, &forward_addr.sin_addr) <= 0) {
        perror("Invalid forward address");
        close(forward_sock);
        return -1;
    }

    if (connect(forward_sock, (struct sockaddr *)&forward_addr, sizeof(forward_addr)) < 0) {
        perror("Forward connection failed");
        close(forward_sock);
        return -1;
    }

    if (packet_count < THRESHOLD) {
        memcpy(packet_buffer[packet_count].data, buffer, buffer_len);
        packet_buffer[packet_count].len = buffer_len;
        packet_count++;
        close(forward_sock);
        return 0; 
    }

    ssize_t total_sent = 0;
    for (int i = 0; i < THRESHOLD; i++) {
        ssize_t sent = send(forward_sock, packet_buffer[i].data, packet_buffer[i].len, 0);
        if (sent > 0) {
            total_sent += sent;
        }
    }
    
    if (total_sent <= 0) {
        perror("Forward send failed");
        close(forward_sock);
        return -1;
    }

    packet_count = 0;
    close(forward_sock);
    return 0;
}

void handle_client(int client_socket, const char* client_ip) {
    ClientInfo *client = find_or_create_client(client_ip);
    if (!client) {
        send(client_socket, "Server overload", 15, 0);
        close(client_socket);
        return;
    }

    if (check_rate_limiting(client)) {
        send(client_socket, "Rate limit exceeded", 18, 0);
        close(client_socket);
        return;
    }

    char buffer[BUFFER_SIZE] = {0};
    ssize_t bytes_read = recv(client_socket, buffer, BUFFER_SIZE-1, 0);
    
    if (bytes_read <= 0) {
        close(client_socket);
        return;
    }

    buffer[bytes_read] = '\0';
    printf("Received from %s: %s\n", client_ip, buffer);

    json_error_t error;
    json_t *root = json_loads(buffer, 0, &error);
    if (!root) {
        send(client_socket, "ERROR: Invalid JSON", 18, 0);
        close(client_socket);
        return;
    }

    json_t *pass_json = json_object_get(root, "password");
    if (!json_is_string(pass_json)) {
        send(client_socket, "ERROR: Invalid password format", 29, 0);
        json_decref(root);
        close(client_socket);
        return;
    }

    const char *password = json_string_value(pass_json);
    if (authenticate(password, client_ip)) {
        send(client_socket, "OK", 2, 0);
        forward_data(client_socket, buffer, bytes_read);
    } else {
        send(client_socket, "ERROR: Authentication failed", 28, 0);
    }

    json_decref(root);
    close(client_socket);
}

#ifndef TESTING
int main() {
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    memset(clients, 0, sizeof(clients));
    pthread_mutex_init(&lock, NULL);
    pthread_t checker_thread;
    pthread_create(&checker_thread, NULL, check_connections, NULL);

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("Setsockopt failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 10) < 0) {
        perror("Listen failed");
        close(server_fd); 
        exit(EXIT_FAILURE);
    }

    printf("Server listening on port %d\n", PORT);

    while (running) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_socket = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        
        if (client_socket < 0) {
            if (running) perror("Accept failed");
            continue;
        }

        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);

        if (is_banned(client_ip)) {
            const char *msg = "ERROR: Your IP is temporarily banned";
            send(client_socket, msg, strlen(msg), 0);
            close(client_socket);
            continue;
        }

        log_request(client_ip);
        handle_client(client_socket, client_ip);
    }

    printf("Shutting down server...\n");
    close(server_fd);
    pthread_join(checker_thread, NULL);
    pthread_mutex_destroy(&lock);
    return 0;
}
#endif