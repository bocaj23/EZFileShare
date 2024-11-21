#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdatomic.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

// IN PROGRESS

// Need certificate (server.crt) and a private key (server.key)
// Command to generate: openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes
// gcc -o tls_application.exe tls_application.c -lws2_32 -lssl -lcrypto

#define SERVER_IP "127.0.0.1"
#define PORT 4443
#define BUFFER_SIZE 1024

// Global flag for termination
volatile atomic_int stop_flag = 0;
volatile atomic_int ready_to_transfer = 0;
pthread_mutex_t transfer_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t transfer_cond = PTHREAD_COND_INITIALIZER;

// Function declarations
void initialize_winsock() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        fprintf(stderr, "WSAStartup failed.\n");
        exit(EXIT_FAILURE);
    }
}

void cleanup_openssl() {
    EVP_cleanup();
}

void cleanup_winsock() {
    WSACleanup();
}

void initialize_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

SSL_CTX *create_client_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_client_method();  // Use TLSv1.2 or newer
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

void configure_client_context(SSL_CTX *ctx) {
    if (SSL_CTX_load_verify_locations(ctx, "server.crt", NULL) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);  // Verify server certificate
}

SSL_CTX *create_server_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_server_method();  // Use TLSv1.2 or newer
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

void configure_server_context(SSL_CTX *ctx) {
    if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

int file_exists(const char *file_path) {
    FILE *file = fopen(file_path, "rb");
    if (file) {
        fclose(file);
        return 1; // File exists
    }
    return 0; // File does not exist
}

void send_file(SSL *ssl, const char *file_path) {
    FILE *file = fopen(file_path, "rb");
    if (!file) {
        perror("Unable to open file");
        return;
    }

    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    printf("Sending file size: %ld bytes\n", file_size);
    if (SSL_write(ssl, &file_size, sizeof(file_size)) <= 0) {
        ERR_print_errors_fp(stderr);
        fclose(file);
        return;
    }

    char buffer[BUFFER_SIZE];
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        if (SSL_write(ssl, buffer, bytes_read) <= 0) {
            ERR_print_errors_fp(stderr);
            fclose(file);
            return;
        }
    }

    fclose(file);
    printf("File sent.\n");
}

void receive_file(SSL *ssl, const char *output_path) {
    long expected_file_size;
    if (SSL_read(ssl, &expected_file_size, sizeof(expected_file_size)) <= 0) {
        ERR_print_errors_fp(stderr);
        return;
    }
    printf("Receiving file of size: %ld bytes\n", expected_file_size);

    FILE *file = fopen(output_path, "wb");
    if (!file) {
        perror("Unable to open file");
        return;
    }

    char buffer[BUFFER_SIZE];
    long bytes_received = 0;
    while (bytes_received < expected_file_size) {
        int bytes = SSL_read(ssl, buffer, sizeof(buffer));
        if (bytes <= 0) {
            ERR_print_errors_fp(stderr);
            fclose(file);
            return;
        }
        fwrite(buffer, 1, bytes, file);
        bytes_received += bytes;
    }

    fclose(file);
    printf("File received successfully.\n");
}

// Server thread function
void *server_thread(void *arg) {
    int sock;
    struct sockaddr_in addr, client_addr;
    socklen_t len;
    SSL_CTX *ctx;
    SSL *ssl;

    initialize_winsock();
    initialize_openssl();

    ctx = create_server_context();
    configure_server_context(ctx);

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        perror("Unable to create socket");
        SSL_CTX_free(ctx);
        cleanup_openssl();
        cleanup_winsock();
        pthread_exit(NULL);
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR) {
        perror("Unable to bind");
        closesocket(sock);
        SSL_CTX_free(ctx);
        cleanup_openssl();
        cleanup_winsock();
        pthread_exit(NULL);
    }

    if (listen(sock, 1) == SOCKET_ERROR) {
        perror("Unable to listen");
        closesocket(sock);
        SSL_CTX_free(ctx);
        cleanup_openssl();
        cleanup_winsock();
        pthread_exit(NULL);
    }

    printf("Server is running and waiting for connections...\n");

    len = sizeof(client_addr);
    int client_sock = accept(sock, (struct sockaddr *)&client_addr, &len);
    if (client_sock == INVALID_SOCKET) {
        perror("Accept failed");
        closesocket(sock);
        SSL_CTX_free(ctx);
        cleanup_openssl();
        cleanup_winsock();
        pthread_exit(NULL);
    }

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, client_sock);
    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        closesocket(client_sock);
        SSL_CTX_free(ctx);
        cleanup_openssl();
        cleanup_winsock();
        pthread_exit(NULL);
    }

    pthread_mutex_lock(&transfer_mutex);
    while (!ready_to_transfer) {
        pthread_cond_wait(&transfer_cond, &transfer_mutex);
    }
    pthread_mutex_unlock(&transfer_mutex);

    receive_file(ssl, "received_file.txt");

    SSL_shutdown(ssl);
    SSL_free(ssl);
    closesocket(client_sock);
    closesocket(sock);
    SSL_CTX_free(ctx);
    cleanup_openssl();
    cleanup_winsock();
    pthread_exit(NULL);
}

// Client function
void client() {

    char file_path[BUFFER_SIZE];
    printf("Enter the file path to send: ");
    fgets(file_path, sizeof(file_path), stdin);
    file_path[strcspn(file_path, "\n")] = '\0';  // Remove newline

    if (!file_exists(file_path)) {
        fprintf(stderr, "File does not exist: %s\n", file_path);
        return;
    }

    SOCKET sock;
    struct sockaddr_in server_addr;
    SSL_CTX *ctx;
    SSL *ssl;

    initialize_winsock();
    initialize_openssl();

    ctx = create_client_context();
    configure_client_context(ctx);

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        perror("Unable to create socket");
        cleanup_winsock();
        cleanup_openssl();
        return;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    if (inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr) <= 0) {
        perror("Invalid server IP address");
        closesocket(sock);
        cleanup_winsock();
        cleanup_openssl();
        return;
    }

    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        perror("Connection failed");
        closesocket(sock);
        cleanup_winsock();
        cleanup_openssl();
        return;
    }

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        closesocket(sock);
        SSL_CTX_free(ctx);
        cleanup_openssl();
        cleanup_winsock();
        return;
    }

    pthread_mutex_lock(&transfer_mutex);
    ready_to_transfer = 1;
    pthread_cond_signal(&transfer_cond);
    pthread_mutex_unlock(&transfer_mutex);

    send_file(ssl, file_path);

    SSL_shutdown(ssl);
    SSL_free(ssl);
    closesocket(sock);
    SSL_CTX_free(ctx);
    cleanup_openssl();
    cleanup_winsock();
}


// Main function
int main() {
    pthread_t server_thread_id;

    // Start the server thread
    if (pthread_create(&server_thread_id, NULL, server_thread, NULL) != 0) {
        perror("Failed to create server thread");
        exit(EXIT_FAILURE);
    }

    // Main loop for user input
    while (!stop_flag) {
        printf("Enter 'send' to send a file, or 'exit' to stop the application:\n");
        char command[10];
        fgets(command, sizeof(command), stdin);
        command[strcspn(command, "\n")] = '\0'; // Remove trailing newline

        if (strcmp(command, "send") == 0) {
            client();
        } else if (strcmp(command, "exit") == 0) {
            stop_flag = 1;
        } else {
            printf("Unknown command. Try 'send' or 'exit'.\n");
        }
    }

    // Wait for the server thread to finish
    pthread_join(server_thread_id, NULL);

    printf("Application stopped.\n");
    return 0;
}