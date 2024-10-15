#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

// Function to convert hex string to byte array
int hex_to_bytes(const char *hex, unsigned char *bytes, size_t bytes_len) {
    size_t hex_len = strlen(hex);
    for (size_t i = 0; i < hex_len / 2 && i < bytes_len; i++) {
        sscanf(&hex[2 * i], "%2hhx", &bytes[i]);
    }
    return hex_len / 2;
}

// Function to perform HKDF-Expand-Label
int hkdf_expand_label(const unsigned char *prk, size_t prk_len,
                      const char *label, const unsigned char *context, size_t context_len,
                      unsigned char *output, size_t length) {
    const char *tls13_prefix = "tls13 ";
    size_t label_len = strlen(label) + strlen(tls13_prefix);
    size_t info_len = 2 + 1 + label_len + 1 + context_len; // Length + Label length + Label + Context length + Context

    unsigned char info[info_len];
    size_t offset = 0;

    // Fill info buffer
    info[offset++] = (length >> 8) & 0xFF;
    info[offset++] = length & 0xFF;
    info[offset++] = label_len;

    memcpy(info + offset, tls13_prefix, strlen(tls13_prefix));
    offset += strlen(tls13_prefix);
    memcpy(info + offset, label, strlen(label));
    offset += strlen(label);

    info[offset++] = context_len;
    memcpy(info + offset, context, context_len);

    unsigned char t[EVP_MAX_MD_SIZE]; // Buffer to store each HMAC output
    size_t t_len = 0;
    size_t out_len = 0;
    unsigned int hash_len = EVP_MD_size(EVP_sha384());

    unsigned char counter = 1;
    while (out_len < length) {
        HMAC_CTX *hmac_ctx = HMAC_CTX_new();
        HMAC_Init_ex(hmac_ctx, prk, prk_len, EVP_sha384(), NULL);

        // Input is previous T value (if any), info, and counter
        if (t_len > 0) {
            HMAC_Update(hmac_ctx, t, t_len);
        }
        HMAC_Update(hmac_ctx, info, info_len);
        HMAC_Update(hmac_ctx, &counter, 1);
        HMAC_Final(hmac_ctx, t, &t_len);

        HMAC_CTX_free(hmac_ctx);

        // Copy the required bytes to output buffer
        size_t to_copy = (out_len + t_len > length) ? (length - out_len) : t_len;
        memcpy(output + out_len, t, to_copy);
        out_len += to_copy;
        counter++;
    }

    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 5) {
        fprintf(stderr, "Usage: %s <prk_hex> <label> <context_hex> <length>\n", argv[0]);
        return 1;
    }

    const char *hexprk = argv[1];
    const char *label = argv[2];
    const char *hexcontext = argv[3];
    size_t length = atoi(argv[4]);

    // Convert hex PRK and context to binary
    unsigned char prk[EVP_MAX_MD_SIZE];
    unsigned char context[1024]; // Adjust as needed
    size_t prk_len = hex_to_bytes(hexprk, prk, sizeof(prk));
    size_t context_len = hex_to_bytes(hexcontext, context, sizeof(context));

    unsigned char output[length];
    hkdf_expand_label(prk, prk_len, label, context, context_len, output, length);

    // Print the output as hex
    for (size_t i = 0; i < length; i++) {
        printf("%02x", output[i]);
    }
    printf("\n");

    return 0;
}
