#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

// Link with ws2_32.lib
//#pragma comment(lib, "ws2_32.lib")

//gcc -o tls_client.exe tls_client.c -lws2_32 -lssl -lcrypto
//./tls_client

#define PORT 4443
#define BUFFER_SIZE 1024
#define SERVER_IP "127.0.0.1"     // Replace with server's IP if needed
#define FILE_TO_SEND "file_to_send.txt"  // File to be sent to server

void initialize_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl() {
    EVP_cleanup();
}

void initialize_winsock() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        fprintf(stderr, "WSAStartup failed.\n");
        exit(EXIT_FAILURE);
    }
}

void cleanup_winsock() {
    WSACleanup();
}

SSL_CTX *create_context() {
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

void configure_context(SSL_CTX *ctx) {
    // Load the trusted CA certificate for verifying the server
    if (SSL_CTX_load_verify_locations(ctx, "server.crt", NULL) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);  // Verify server certificate
}

int main() {
    SOCKET sock;
    struct sockaddr_in server_addr;
    SSL_CTX *ctx;
    SSL *ssl;

    initialize_winsock();
    initialize_openssl();
    ctx = create_context();
    configure_context(ctx);

    // Create TCP socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        perror("Unable to create socket");
        WSACleanup();
        exit(EXIT_FAILURE);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    if (inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr) <= 0) {
        perror("Invalid address or address not supported");
        closesocket(sock);
        cleanup_winsock();
        exit(EXIT_FAILURE);
    }

    // Connect to the server
    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        perror("Connection failed");
        closesocket(sock);
        cleanup_winsock();
        exit(EXIT_FAILURE);
    }

    // Wrap socket with SSL
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
    } else {
        printf("Connected to server with TLS.\n");

        // Open file to send
        FILE *file = fopen(FILE_TO_SEND, "rb");
        if (!file) {
            perror("Unable to open file");
            SSL_shutdown(ssl);
            SSL_free(ssl);
            closesocket(sock);
            SSL_CTX_free(ctx);
            cleanup_openssl();
            cleanup_winsock();
            exit(EXIT_FAILURE);
        }

        // Read file and send over TLS
        char buffer[BUFFER_SIZE];
        int bytes;
        while ((bytes = fread(buffer, 1, BUFFER_SIZE, file)) > 0) {
            if (SSL_write(ssl, buffer, bytes) <= 0) {
                perror("Failed to send file data");
                ERR_print_errors_fp(stderr);
                break;
            }
        }
        printf("File sent successfully.\n");

        fclose(file);
    }

    // Clean up
    SSL_shutdown(ssl);
    SSL_free(ssl);
    closesocket(sock);
    SSL_CTX_free(ctx);
    cleanup_openssl();
    cleanup_winsock();
    return 0;
}