#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>   /* Internet address family for structures like sockaddr_in. */
#include <jansson.h>
#include <sys/epoll.h>
#include <arpa/inet.h>    /* Internet address conversion functions like inet_ntoa. */
#include <errno.h>        /* Error number definitions (e.g., EWOULDBLOCK, EINTR). */
#include <ctype.h>

#define PORT 8082
#define BUFFER_SIZE 1024

int authenticate(const char *password) {
    if (strcmp(password, "password") == 0) {
        return 1;
    } else {
        return 0; 
    }
}

// void handle_connection(int socket) {
//     char buffer[BUFFER_SIZE] = {0}; /* Character array to store the data received from the >    int bytes_received;
//     char json_response[2048] = {0};
//     char http_response[2048] = {0};/* Integer to store the number of bytes received from th>
//     // Get client IP address
//     struct sockaddr_in client_address;
//     socklen_t client_len = sizeof(client_address);
//     getpeername(socket, (struct sockaddr*)&client_address, &client_len);
//     char* client_ip = inet_ntoa(client_address.sin_addr);
//     int client_port = ntohs(client_address.sin_port);

//     printf("New connection from %s:%d\n", client_ip, client_port);

//     // Read data from the socket
//     bytes_received = read(socket, buffer, BUFFER_SIZE - 1);  /* Read data from the client s>
//     if (bytes_received > 0) {  /* If bytes were received from the client */
//         buffer[bytes_received] = '\0'; /* Null-terminate the received data. */
//         printf("Received: %s\n", buffer); /* Print the data received from the client to the>    } else if (bytes_received == 0) { /* If client disconnected */
//         printf("Client disconnected\n"); /* Print a message to the console indicating that >    } else {
//         perror("recv failed"); /* If an error occurred during data reception */
//     }
//     buffer[bytes_received] = '\0';

//     // http parser
//     /*
//     char method[16] = {0}
//     Declares a 16-byte method array for storing HTTP methods (GET, POST, etc.) and initiali>    This is important to ensure that the array starts with an empty string.

//     char uri[256] = {0}
//     Declares a 256 byte uri array for storing the URI (Uniform Resource Identifier) and ini>
//     char *http_version = NULL
//     Declares an http_version pointer to a string for storing the HTTP version (for example,>    Using NULL is useful here, as it allows you to check if space has been allocated for ht>
// char *request_line_end =str str(buffer, "\r\n")
//     Uses the strstr function to search for the first occurrence of newline characters (\r\n>    The result (a pointer to the beginning of \r\t) is saved in request_line_end. \r\t usua>    */
//     char method[16] = {0};
//     char uri[256] = {0};
//     char *http_version = NULL;
//     char *request_line_end = strstr(buffer, "\r\n");

//     if (request_line_end == NULL) {
//       const char* error_response = "HTTP/1.1 400 Bad Request\nContent-Type: text/plain\n\nI>      send(socket, error_response, strlen(error_response), 0);
//       close(socket);
//       return;
//     }

//         if (http_version == NULL) {
//         const char* error_response = "HTTP/1.1 400 Bad Request\nContent-Type: text/plain\n\>        send(socket, error_response, strlen(error_response), 0);
//         close(socket);
//         return;
//     }
//     // Parse the HTTP method, URI, and version
//     sscanf(buffer, "%15s %255s %ms", method, uri, &http_version);

//     printf("Method: %s, URI: %s\n", method, uri);
//     printf("HTTP Version: %s\n", http_version);

//     // Извлекаем заголовки
//     char *header_start = request_line_end + 2; // Пропускаем \r\n
//     char *header_end = strstr(header_start, "\r\n\r\n");

//     char headers[2048] = {0};
//     if (header_end != NULL) {
//         int header_length = header_end - header_start;
//         url_decode(headers, header_start, header_length);
//         headers[header_length] = '\0';
//         printf("Headers:\n%s\n", headers);
//     } else {
//         const char* error_response = "HTTP/1.1 400 Bad Request\nContent-Type: text/plain\n\nInvalid Headers";
//         send(socket, error_response, strlen(error_response), 0);
//         close(socket);
//         return;
//     }
//     if (strcmp(method, "GET") == 0) {
//         if (strcmp(uri, "/") == 0) { // Главная страница
//              snprintf(json_response, sizeof(json_response),
//                     "{\"message\": \"Welcome to my server!\", \"ip\": \"%s\", \"port\": %d}",
//                     client_ip, client_port);
//         } else if (strcmp(uri, "/hello") == 0) {
//              snprintf(json_response, sizeof(json_response),
//                     "{\"message\": \"Hello, world!\", \"client_ip\": \"%s\", \"method\": \"%s\"}",
//                     client_ip, method);
//         } else if (strcmp(uri, "/headers") == 0) {
//               char encoded_headers[4096] = {0};
//               url_decode(encoded_headers, headers, sizeof(encoded_headers));
//              snprintf(json_response, sizeof(json_response),
//                      "{\"headers\": \"%s\"}", encoded_headers); // Кодируем заголовки для корректной передачи в JSON
//         }
//         else {
//             // 404 Not Found
//             snprintf(http_response, sizeof(http_response),
//                 "HTTP/1.1 404 Not Found\nContent-Type: text/plain\nContent-Length: 9\n\nNot Found");
//             send(socket, http_response, strlen(http_response), 0);
//             close(socket);
//             return; // Exit function to avoid sending the JSON response
//         }

//         // Формируем HTTP-ответ с JSON
//         snprintf(http_response, sizeof(http_response),
//                 "HTTP/1.1 200 OK\nContent-Type: application/json\nContent-Length: %ld\n\n%s",
//                 strlen(json_response), json_response);
//         send(socket, http_response, strlen(http_response), 0);

//     } else {
//         // Обработка других методов (POST, PUT, DELETE и т.д.)  (TODO)
//         const char* error_response = "HTTP/1.1 501 Not Implemented\nContent-Type: text/plain\n\nNot Implemented";
//         send(socket, error_response, strlen(error_response), 0);
//     }

//     free(http_version); //

//     const char* response = "HTTP/1.1 200 OK\nContent-Type: text/plain\n\nHello from the server!";
//     send(socket, response, strlen(response), 0);

//     close(socket); /* Close the client socket. */
//     printf("Connection closed\n");/* Print a message to the console indicating that the connection has been closed. */
// }
    
int main() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    char buffer[BUFFER_SIZE] = {0};

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 3) < 0) {
        perror("listen failed");
        exit(EXIT_FAILURE);
    }
    
    printf("Listening on port %d\n", PORT);

    if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen))<0) {
        perror("accept failed");
        exit(EXIT_FAILURE);
    }

    read(new_socket, buffer, BUFFER_SIZE);
    printf("Received: %s\n", buffer);

    json_error_t error;
    json_t *root = json_loads(buffer, 0, &error);

    if (!root) {
        fprintf(stderr, "Error: %s\n", error.text);
        send(new_socket, "ERROR: Invalid JSON", strlen("ERROR: Invalid JSON"), 0);
    } else {
        json_t *password_json = json_object_get(root, "password");

        if (!json_is_string(password_json)) {
            fprintf(stderr, "Error: username or password missing or not a string\n");
            send(new_socket, "ERROR: Invalid username or password", strlen("ERROR: Invalid username or password"), 0);
        } else {
            const char *password = json_string_value(password_json);

            if (authenticate(password)) {
                send(new_socket, "OK", strlen("OK"), 0);
            } else {
                send(new_socket, "ERROR: Authentication failed", strlen("ERROR: Authentication failed"), 0);
            }
        }
        json_decref(root);
    }

    close(new_socket);
    close(server_fd);
    return 0;
}