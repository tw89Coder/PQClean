/**
 * ML-KEM-768 (Kyber) Vulnerable Server Implementation
 * Course Project: Side-Channel Attack Proof-of-Concept
 * * Description: 
 * This server implements a modified version of the ML-KEM-768 decapsulation 
 * routine. It supports Key Persistence to ensure deterministic behavior 
 * across restarts, allowing for consistent testing of "Secure" vs "Vulnerable" 
 * states using the same Private Key.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/stat.h> 
#include "crypto_kem/ml-kem-768/clean/api.h"

#define PORT 8080
#define SK_FILE "server_sk.bin" // File to store/load the persistent Secret Key

// ANSI Color Codes for Terminal Output
#define RED     "\033[1;31m"
#define GREEN   "\033[1;32m"
#define YELLOW  "\033[1;33m"
#define CYAN    "\033[1;36m"
#define RESET   "\033[0m"

// Helper function to print hex values for visual verification
void print_hex(const char *label, const uint8_t *data, size_t len, const char *color) {
    printf("%s%s", color, label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("%s\n", RESET);
}

/**
 * [Key Persistence Helper]
 * Loads the Secret Key from disk if it exists; otherwise, generates a new pair
 * and saves the Secret Key. This ensures the server always acts as the same
 * cryptographic identity, which is crucial for verifying if the Oracle
 * is behaving differently (Random vs. Deterministic) under attack.
 */
void load_or_gen_key(uint8_t *pk, uint8_t *sk) {
    FILE *fp = fopen(SK_FILE, "rb");
    if (fp) {
        printf(YELLOW "[Init] Persistence: Loading existing Private Key from '%s'...\n" RESET, SK_FILE);
        // We only strictly need the Secret Key for decapsulation
        size_t read_len = fread(sk, 1, PQCLEAN_MLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES, fp);
        if (read_len != PQCLEAN_MLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES) {
             printf(RED "[Error] Key file corrupted. Please delete %s and restart.\n" RESET, SK_FILE);
             exit(1);
        }
        fclose(fp);
        
        // Generate a dummy Public Key to fill the buffer (not used for decapsulation)
        // In a full implementation, we would save/load the PK as well.
        printf(YELLOW "[Init] Keypair loaded successfully.\n" RESET);
    } else {
        printf(YELLOW "[Init] First Run: Generating NEW Keypair and saving to '%s'...\n" RESET, SK_FILE);
        PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair(pk, sk);
        
        fp = fopen(SK_FILE, "wb");
        if (!fp) {
            perror("File Error");
            exit(EXIT_FAILURE);
        }
        fwrite(sk, 1, PQCLEAN_MLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES, fp);
        fclose(fp);
        printf(GREEN "[Init] Key saved. The server will now use this key for all future runs.\n" RESET);
    }
}

int main() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    
    // Cryptographic buffers
    uint8_t pk[PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[PQCLEAN_MLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES];
    uint8_t ct[PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES];
    uint8_t ss[PQCLEAN_MLKEM768_CLEAN_CRYPTO_BYTES];
    
    // 1. Key Initialization (Persistent)
    load_or_gen_key(pk, sk);

    printf(YELLOW "[Init] Vulnerable Server listening on port %d...\n" RESET, PORT);

    // 2. Network Initialization
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY; 
    address.sin_port = htons(PORT);
    
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }
    
    if (listen(server_fd, 3) < 0) {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }

    while(1) {
        printf("\n" CYAN "--- Waiting for Client Connection ---" RESET "\n");
        new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen);
        
        int valread = read(new_socket, ct, sizeof(ct));
        
        // 3. Vulnerability Trigger Check
        if (valread == PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES) {
            printf(RED "[ALERT] Potential Attack Vector Received (%d bytes)\n" RESET, valread);
            printf(RED "[VULN] Executing Decapsulation...\n" RESET);
            
            // Execute the decapsulation (Vulnerability depends on compile-time kem.c state)
            PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(ss, ct, sk);
            
            // Display the calculated secret. 
            // IMPORTANT: Copy this value to your Python script during the "Vulnerable" phase.
            print_hex("[DEBUG] Calculated Shared Secret: ", ss, PQCLEAN_MLKEM768_CLEAN_CRYPTO_BYTES, YELLOW);
            
            // Return the calculated key to the client (Oracle Response)
            send(new_socket, ss, PQCLEAN_MLKEM768_CLEAN_CRYPTO_BYTES, 0);
        } else {
            // Handle standard HTTP traffic
            char *msg = "HTTP/1.1 200 OK\r\n\r\n";
            send(new_socket, msg, strlen(msg), 0);
        }
        
        close(new_socket);
    }
    return 0;
}