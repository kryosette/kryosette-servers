#include "code.h"

/*
SSL_CTX *create_ssl_context(const char *cert_path, const char *key_path)
{
    SSL_CTX *ctx;

    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx)
    {
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    if (SSL_CTX_use_certificate_file(ctx, cert_path, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, key_path, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }

    if (!SSL_CTX_check_private_key(ctx))
    {
        fprintf(stderr, "Private key does not match the certificate\n");
        SSL_CTX_free(ctx);
        return NULL;
    }

    return ctx;
}
*/

Packet packet_buffer[THRESHOLD];
size_t packet_count = 0;
ClientInfo clients[MAX_CLIENTS] = {0};
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
volatile sig_atomic_t running = 1;

ClientInfo *find_or_create_client(const char *ip)
{
    for (int i = 0; i < MAX_CLIENTS; i++)
    {
        if (strcmp(clients[i].ip, ip) == 0)
        {
            return &clients[i];
        }
    }

    for (int i = 0; i < MAX_CLIENTS; i++)
    {
        if (clients[i].count == 0)
        {
            strncpy(clients[i].ip, ip, INET_ADDRSTRLEN - 1);
            clients[i].ip[INET_ADDRSTRLEN - 1] = '\0';
            clients[i].count = 0;
            clients[i].last_update = time(NULL);
            return &clients[i];
        }
    }
    return NULL;
}

/*
A={x1,x2,…,xk}
The alphabet, i.e., the set of all possible symbols that a (digitized) noise
source produces.

H
The min-entropy of the samples from a (digitized) noise source or of the
output from an entropy source; the min-entropy assessment for a noise
source or entropy source

pi
The probability for an observation (or occurrence) of the symbol xi in A.
*/

/*
*Min-Entropy*

❗Min-entropy measures predictability—it tells you how easily an attacker can guess the
                        most likely outcome of a random process.

Entropy is defined relative to one's knowledge of an experiment's output prior to observation,
and reflects the uncertainty associated with predicting its value – the larger the amount of entropy,
the greater the uncertainty in predicting the value of an observation.

                                - Probabilty -
The probability that a secret is guessed correctly in the first trial is related to the
min-entropy of the distribution that the secret was generated from.

The min-entropy of an independent discrete random variable X that takes values from the set
A={x1,x2,…,xk} with probability Pr(X=xi) = pi for i =1,…,k is defined as

                                𝐻 = min (−log2 p𝑖),
                                    1≤𝑖≤𝑘
                                = − log2 max p𝑖.
                                        1≤𝑖≤𝑘

*/

void max_secure_rand(unsigned char *buf, size_t len)
{
    // Вариант 1: Используем только OpenSSL
    if (RAND_bytes(buf, len) != 1)
    {
        fprintf(stderr, "Ошибка генерации случайных чисел\n");
        abort();
    }

    /*
    // Вариант 2: Альтернативная реализация через /dev/urandom
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f || fread(buf, 1, len, f) != len) {
        if (f) fclose(f);
        fprintf(stderr, "Ошибка чтения /dev/urandom\n");
        abort();
    }
    fclose(f);
    */
}

void secure_pad(unsigned char *data, size_t *current_len, size_t max_len, int mode)
{
    size_t target_len;

    switch (mode)
    {
    case 0: // fixed size
        target_len = max_len;
        break;
    case 1: // Random padding (50-100% of max_len)
        // Use max_secure_rand instead of RAND_bytes
        max_secure_rand((unsigned char *)&target_len, sizeof(target_len));

        // Calculate random padding length safely
        size_t available_space = max_len - *current_len;
        if (available_space == 0)
            return; // No space left

        target_len = *current_len + (target_len % (available_space + 1));
        break;
    case 2:
        target_len = max_len;
        const char *http_headers = "\r\nX-Padding: a1b2c3d4\r\n";
        size_t http_pad_len = strlen(http_headers);
        if (*current_len + http_pad_len <= max_len)
        {
            memcpy(data + *current_len, http_headers, http_pad_len);
            *current_len += http_pad_len;
        }
        return;
    }
    if (target_len <= *current_len)
        return;

    max_secure_rand(data + *current_len, target_len - *current_len);
    *current_len = target_len;
}

void handle_crypto_error(const char *msg)
{
    fprintf(stderr, "Crypto error: %s\n", msg);
    exit(1);
}

void update_rate(ClientInfo *client)
{
    time_t now = time(NULL);
    double elapsed = difftime(now, client->last_update);

    if (elapsed > 0)
    {
        double instant_rate = 1.0 / elapsed;
        client->request_rate = ALPHA * instant_rate + (1 - ALPHA) * client->request_rate;
    }

    client->last_update = now;
}

int check_rate_limiting(ClientInfo *client)
{
    update_rate(client);

    double dynamic_limit = INITIAL_RATE_LIMIT;

    if (client->request_rate > dynamic_limit &&
        client->request_rate < MAX_LEGIT_RATE)
    {
        return 1;
    }

    return 0;
}

void handle_signal(int sig)
{
    running = 0;
}

int authenticate(const char *password, const char *ip)
{
    const char *correct_password = "secure_hashed_password";
    (void)ip;

    return strcmp(password, "password") == 0;
}

void *check_connections(void *arg)
{
    while (running)
    {
        pthread_mutex_lock(&lock);
        time_t now = time(NULL);

        for (int i = 0; i < MAX_CLIENTS; i++)
        {
            if (clients[i].is_banned && now < clients[i].banned_until)
            {
                continue;
            }

            if (clients[i].count > MAX_REQUESTS_PER_SECOND &&
                difftime(now, clients[i].last_request) <= 1)
            {
                clients[i].is_banned = 1;
                clients[i].banned_until = now + BAN_TIME;
                printf("IP %s banned for %d seconds\n", clients[i].ip, BAN_TIME);
            }
            else if (difftime(now, clients[i].last_request) > 1)
            {
                clients[i].count = 0;
                clients[i].is_banned = 0;
            }
        }

        pthread_mutex_unlock(&lock);
        sleep(1);
    }
    return NULL;
}

void log_request(const char *ip)
{
    pthread_mutex_lock(&lock);
    time_t now = time(NULL);
    int found = 0;

    for (int i = 0; i < MAX_CLIENTS; i++)
    {
        if (strcmp(clients[i].ip, ip) == 0)
        {
            clients[i].count++;
            clients[i].last_request = now;
            found = 1;
            break;
        }
    }

    if (!found)
    {
        for (int i = 0; i < MAX_CLIENTS; i++)
        {
            if (clients[i].count == 0)
            {
                strncpy(clients[i].ip, ip, INET_ADDRSTRLEN - 1);
                clients[i].ip[INET_ADDRSTRLEN - 1] = '\0';
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

int is_banned(const char *ip)
{
    pthread_mutex_lock(&lock);
    time_t now = time(NULL);
    int banned = 0;

    for (int i = 0; i < MAX_CLIENTS; i++)
    {
        if (strcmp(clients[i].ip, ip) == 0)
        {
            if (clients[i].is_banned && now < clients[i].banned_until)
            {
                banned = 1;
            }
            break;
        }
    }

    pthread_mutex_unlock(&lock);
    return banned;
}

Error socket_set_timeout(int sockfd, long sec, long usec)
{
    struct timeval timeout = {.tv_sec = sec, .tv_usec = usec};
    if (setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)))
    {
        return (Error){.code = errno, .message = strerror(errno)};
    }

    return (Error){0};
}

Error socket_create_and_connect(const char *ip, int port, int *out_sockfd)
{
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        return (Error){.code = errno, .message = "socket creation failed"};
    }

    Error err = socket_set_timeout(sockfd, 2, 0);
    if (!is_ok(err))
    {
        close(sockfd);
        return err;
    }

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port)};
    if (inet_pton(AF_INET, ip, &addr.sin_addr) <= 0)
    {
        close(sockfd);
        return (Error){.code = EINVAL, .message = "invalid IP address"};
    }

    if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)))
    {
        close(sockfd);
        return (Error){.code = errno, .message = "connection failed"};
    }

    *out_sockfd = sockfd;
    return (Error){0};
}

Error socket_send_all(int sockfd, const char *buffer, size_t buffer_len)
{
    ssize_t sent = send(sockfd, buffer, buffer_len, 0);
    if (sent < 0)
    {
        return (Error){.code = errno, .message = "send failed"};
    }
    if ((size_t)sent != buffer_len)
    {
        return (Error){.code = EPIPE, .message = "partial data sent"};
    }
    return (Error){0};
}

Error forward_data(int client_socket, const char *buffer, size_t buffer_len)
{
    printf("Attempting to forward data to %s:%d\n", FORWARD_IP, FORWARD_PORT);

    int forward_sock;
    Error err = socket_create_and_connect(FORWARD_IP, FORWARD_PORT, &forward_sock);
    if (!is_ok(err))
    {
        return err;
    }

    printf("Sending data to forward node...\n");
    err = socket_send_all(forward_sock, buffer, buffer_len);
    close(forward_sock);

    if (!is_ok(err))
    {
        return err;
    }

    printf("Successfully forwarded %zu bytes\n", buffer_len);
    return (Error){0};
}

void handle_client(int client_socket, const char *client_ip, /*SSL_CTX *ctx,*/ LSMTree *db)
{
    /*
    // Закомментированная SSL часть
    SSL *ssl = SSL_new(ctx);
    if (!ssl)
    {
        ERR_print_errors_fp(stderr);
        close(client_socket);
        return;
    }

    if (SSL_set_fd(ssl, client_socket) != 1)
    {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(client_socket);
        return;
    }

    if (SSL_accept(ssl) <= 0)
    {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(client_socket);
        return;
    }
    */

    char buffer[BUFFER_SIZE] = {0};
    // Заменяем SSL_read на обычный read
    ssize_t bytes_read = read(client_socket, buffer, sizeof(buffer) - 1);

    if (bytes_read <= 0)
    {
        /*
        SSL_shutdown(ssl);
        SSL_free(ssl);
        */
        close(client_socket);
        return;
    }

    buffer[bytes_read] = '\0';
    printf("Received from %s: %s\n", client_ip, buffer);

    char db_key[128];
    snprintf(db_key, sizeof(db_key), "%s:%ld", client_ip, time(NULL));
    lsm_put(db, db_key, buffer);
    printf("Saved data for %s\n", client_ip);

    // Обработка JSON
    json_error_t error;
    json_t *root = json_loads(buffer, 0, &error);
    if (!root)
    {
        // Заменяем SSL_write на обычный send
        send(client_socket, "ERROR: Invalid JSON", 18, 0);
        goto cleanup;
    }

    // Проверка пароля
    json_t *pass_json = json_object_get(root, "password");
    if (!json_is_string(pass_json))
    {
        send(client_socket, "ERROR: Invalid password format", 29, 0);
        json_decref(root);
        goto cleanup;
    }

    // Отправка ответа через обычный send вместо SSL_write
    if (strstr(buffer, "\"password\":\"password\""))
    {
        send(client_socket, "OK", 2, 0);
    }
    else
    {
        send(client_socket, "ERROR: Authentication failed", 28, 0);
    }

cleanup:
    if (root)
        json_decref(root);
    /*
    SSL_shutdown(ssl);
    SSL_free(ssl);
    */
    close(client_socket);
}

#ifndef TESTING
int main()
{
    LSMTree hash_db;
    init_lsm_tree(&hash_db);
    lsm_put(&hash_db, "test", "value");
    struct io_uring ring;
    io_uring_queue_init(ENTRIES, &ring, 0);

    printf("Starting node on port %d, forwarding to %s:%d\n",
           PORT, FORWARD_IP, FORWARD_PORT);
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    memset(clients, 0, sizeof(clients));
    pthread_mutex_init(&lock, NULL);
    pthread_t checker_thread;
    pthread_create(&checker_thread, NULL, check_connections, NULL);

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0)
    {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)))
    {
        perror("Setsockopt failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0)
    {
        perror("Bind failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 10) < 0)
    {
        perror("Listen failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    printf("Server listening on port %d\n", PORT);

    /*
    SSL_CTX *ctx = create_ssl_context("node1.crt", "node1.key");
    if (!ctx)
    {
        fprintf(stderr, "Failed to create SSL context\n");
        return 1;
    }
    */

    while (running)
    {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);

        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(server_fd, &readfds);

        struct timeval timeout = {.tv_sec = 1, .tv_usec = 0};
        int ready = select(server_fd + 1, &readfds, NULL, NULL, &timeout);

        if (ready < 0)
        {
            if (errno == EINTR && !running)
                break;
            perror("select failed");
            continue;
        }

        if (ready == 0)
            continue;

        int client_socket = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_socket < 0)
        {
            if (running)
                perror("accept failed");
            continue;
        }

        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);

        if (is_banned(client_ip))
        {
            const char *msg = "ERROR: Your IP is temporarily banned";
            send(client_socket, msg, strlen(msg), 0);
            close(client_socket);
            continue;
        }

        log_request(client_ip);
        handle_client(client_socket, client_ip, &hash_db);
    }

    save_all_data_to_file(&hash_db);

    printf("Shutting down server...\n");
    close(server_fd);
    pthread_join(checker_thread, NULL);
    pthread_mutex_destroy(&lock);
    /*
    SSL_CTX_free(ctx);
    */
    free_lsm_tree(&hash_db);
    // ERR_print_errors_fp(stderr); // Также закомментировано
    return 0;
}
#endif