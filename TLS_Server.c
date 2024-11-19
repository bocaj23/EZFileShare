#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

// Link with ws2_32.lib
//#pragma comment(lib, "ws2_32.lib")

// Need certificate (server.crt) and a private key (server.key)
// Command to generate: openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes
// Compile with: gcc -o tls_server.exe tls_server.c -lws2_32 -lssl -lcrypto

#define PORT 4443
#define BUFFER_SIZE 1024

void initialize_winsock() {
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        fprintf(stderr, "WSAStartup failed: %d\n", result);
        exit(EXIT_FAILURE);
    }
}

void cleanup_winsock() {
    WSACleanup();
}

void initialize_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl() {
    EVP_cleanup();
}

SSL_CTX *create_context() {
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

void configure_context(SSL_CTX *ctx) {
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

int main() {
    int sock;
    struct sockaddr_in addr;
    SSL_CTX *ctx;
    SSL *ssl;

    // Initialize Winsock and OpenSSL
    initialize_winsock();
    initialize_openssl();

    // Create SSL context and configure it
    ctx = create_context();
    configure_context(ctx);

    // Create socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        perror("Unable to create socket");
        cleanup_winsock();
        cleanup_openssl();
        exit(EXIT_FAILURE);
    }

    // Bind socket to address and port
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        perror("Unable to bind");
        closesocket(sock);
        cleanup_winsock();
        cleanup_openssl();
        exit(EXIT_FAILURE);
    }

    // Listen for incoming connections
    if (listen(sock, 1) == SOCKET_ERROR) {
        perror("Unable to listen");
        closesocket(sock);
        cleanup_winsock();
        cleanup_openssl();
        exit(EXIT_FAILURE);
    }

    while (1) {
        struct sockaddr_in client_addr;
        int len = sizeof(client_addr);
        int client = accept(sock, (struct sockaddr*)&client_addr, &len);

        if (client == INVALID_SOCKET) {
            perror("Unable to accept");
            closesocket(sock);
            cleanup_winsock();
            cleanup_openssl();
            exit(EXIT_FAILURE);
        }

        // Create SSL object and associate it with the client socket
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client);

        // Perform SSL/TLS handshake
        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
        } else {
            char buffer[BUFFER_SIZE];
            int bytes;
            FILE *file = fopen("received_file.txt", "wb");

            if (!file) {
                perror("Unable to open file for writing");
                SSL_shutdown(ssl);
                SSL_free(ssl);
                closesocket(client);
                continue;
            }

            // Receive file data over SSL/TLS
            while ((bytes = SSL_read(ssl, buffer, sizeof(buffer))) > 0) {
                fwrite(buffer, 1, bytes, file);
            }

            fclose(file);
            printf("File received successfully!\n");
        }

        // Clean up SSL and close client connection
        SSL_shutdown(ssl);
        SSL_free(ssl);
        closesocket(client);
    }

    // Clean up server socket, SSL context, and libraries
    closesocket(sock);
    SSL_CTX_free(ctx);
    cleanup_openssl();
    cleanup_winsock();
    return 0;
}