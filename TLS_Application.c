#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdatomic.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

//IN PROGRESS

// Need certificate (server.crt) and a private key (server.key)
// Command to generate: openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes
// gcc -o tls_application.exe tls_application.c -lws2_32 -lssl -lcrypto

#define SERVER_IP "127.0.0.1"
#define PORT 4443
#define BUFFER_SIZE 1024
#define FILE_TO_SEND "file_to_send.txt"

// Global flag for termination
volatile atomic_int stop_flag = 0;

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
    // Load the trusted CA certificate for verifying the server
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
    // Set the server's certificate and private key
    if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

void send_file(SSL *ssl, const char *file_path) {
    FILE *file = fopen(file_path, "rb");
    if (!file) {
        perror("Unable to open file");
        return;
    }

    // Get file size
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    // Send file size
    printf("Sending file size: %ld bytes\n", file_size);
    if (SSL_write(ssl, &file_size, sizeof(file_size)) <= 0) {
        ERR_print_errors_fp(stderr);
        fclose(file);
        return;
    }

    // Send file data
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
    // Receive file size
    long expected_file_size;
    if (SSL_read(ssl, &expected_file_size, sizeof(expected_file_size)) <= 0) {
        ERR_print_errors_fp(stderr);
        return;
    }
    printf("Receiving file of size: %ld bytes\n", expected_file_size);

    // Open file for writing
    FILE *file = fopen(output_path, "wb");
    if (!file) {
        perror("Unable to open file");
        return;
    }

    // Receive file data
    char buffer[BUFFER_SIZE];
    long bytes_received = 0;
    while (bytes_received < expected_file_size) {
        int bytes = SSL_read(ssl, buffer, sizeof(buffer));
        if (bytes <= 0) {
            int err = SSL_get_error(ssl, bytes);
            printf("Bytes: %d, Error: %d\n", bytes, err);
            switch(err) {
                case SSL_ERROR_WANT_READ:
                    fprintf(stderr, "SSL_ERROR_WANT_READ\n");
                    break;
                case SSL_ERROR_WANT_WRITE:
                    fprintf(stderr, "SSL_ERROR_WANT_WRITE\n");
                    break;
                case SSL_ERROR_ZERO_RETURN:
                    fprintf(stderr, "SSL_ERROR_ZERO_RETURN - Connection closed\n");
                    break;
                case SSL_ERROR_SYSCALL:
                    fprintf(stderr, "SSL_ERROR_SYSCALL - IO error: %d\n", WSAGetLastError());
                    break;
                default:
                    fprintf(stderr, "SSL_read failed. Error code: %d\n", err);
                    ERR_print_errors_fp(stderr);
            }
            fclose(file);
            return;
        }
        fwrite(buffer, 1, bytes, file);
        bytes_received += bytes;
        printf("Received %ld of %ld bytes\n", bytes_received, expected_file_size);
    }

    fclose(file);

    // Verify file size
    printf("File received successfully. Verifying size...\n");
    FILE *received_file = fopen(output_path, "rb");
    if (!received_file) {
        perror("Unable to open received file for verification");
        return;
    }
    fseek(received_file, 0, SEEK_END);
    long actual_file_size = ftell(received_file);
    fclose(received_file);

    if (actual_file_size == expected_file_size) {
        printf("File size verification succeeded. File size: %ld bytes.\n", actual_file_size);
    } else {
        printf("File size mismatch! Expected: %ld bytes, Received: %ld bytes.\n", expected_file_size, actual_file_size);
    }
}

// Server thread function
void *server_thread(void *arg) {
    int sock;
    struct sockaddr_in addr, client_addr;
    socklen_t len;
    SSL_CTX *ctx;
    SSL *ssl;

    // Initialize Winsock and OpenSSL
    initialize_winsock();
    initialize_openssl();

    // Create and configure SSL context
    ctx = create_server_context();
    if (!ctx) {
        fprintf(stderr, "Failed to create SSL context\n");
        pthread_exit(NULL); // Terminate thread safely
    }

    configure_server_context(ctx);

    // Create socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        perror("Unable to create socket");
        SSL_CTX_free(ctx);
        cleanup_openssl();
        cleanup_winsock();
        pthread_exit(NULL);
    }

    // Bind to port
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

    // Listen for connections
    if (listen(sock, 1) == SOCKET_ERROR) {
        perror("Unable to listen");
        closesocket(sock);
        SSL_CTX_free(ctx);
        cleanup_openssl();
        cleanup_winsock();
        pthread_exit(NULL);
    }

    printf("Server is running and waiting for connections...\n");

    fd_set read_fds;
    struct timeval timeout;

    while (!stop_flag) {
        FD_ZERO(&read_fds);
        FD_SET(sock, &read_fds);

        timeout.tv_sec = 1;  // Check every 1 second
        timeout.tv_usec = 0;

        int activity = select(sock + 1, &read_fds, NULL, NULL, &timeout);

        if (activity > 0 && FD_ISSET(sock, &read_fds)) {
            len = sizeof(client_addr);
            int client_sock = accept(sock, (struct sockaddr *)&client_addr, &len);
            if (client_sock == INVALID_SOCKET) {
                if (stop_flag) break; // Exit cleanly if stop_flag is set
                perror("Accept failed");
                continue;
            }

            // SSL handshake
            ssl = SSL_new(ctx);
            SSL_set_fd(ssl, client_sock);
            if (SSL_accept(ssl) <= 0) {
                ERR_print_errors_fp(stderr);
            } else {
                printf("Client connected. Receiving file...\n");
                receive_file(ssl, "received_file.txt");
            }

            // Clean up SSL and socket
            SSL_shutdown(ssl);
            SSL_free(ssl);
            closesocket(client_sock);
        }
    }

    // Clean up
    closesocket(sock);
    SSL_CTX_free(ctx);
    cleanup_openssl();
    cleanup_winsock();

    pthread_exit(NULL); // Explicit termination
    return NULL;        // Fallback for compiler satisfaction
}

// Client function
void client() {
    SOCKET sock;
    struct sockaddr_in server_addr;
    SSL_CTX *ctx;
    SSL *ssl;

    // Initialize libraries
    initialize_winsock();
    initialize_openssl();

    // Create and configure SSL context
    ctx = create_client_context();
    configure_client_context(ctx);

    // Create socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        perror("Unable to create socket");
        cleanup_winsock();
        cleanup_openssl();
        return;
    }

    // Set up server address
    memset(&server_addr, 0, sizeof(server_addr));  // Initialize the structure to zero
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    if (inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr) <= 0) {
        perror("Invalid server IP address");
        closesocket(sock);
        cleanup_winsock();
        cleanup_openssl();
        return;
    }

    // Connect to server
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        perror("Connection failed");
        closesocket(sock);
        cleanup_winsock();
        cleanup_openssl();
        return;
    }

    // Establish SSL connection
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

    printf("Connected to server with TLS. Sending file...\n");

    // Send the file
    send_file(ssl, FILE_TO_SEND);

    // Clean up
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