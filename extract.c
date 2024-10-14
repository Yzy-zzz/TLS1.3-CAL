#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

// 将十六进制字符串转换为二进制数据
unsigned char* hex_to_bin(const char* hex, size_t* out_len) {
    size_t len = strlen(hex);
    if (len % 2 != 0) {
        return NULL;
    }

    *out_len = len / 2;
    unsigned char* bin = (unsigned char*)malloc(*out_len);
    for (size_t i = 0; i < *out_len; i++) {
        sscanf(hex + 2 * i, "%2hhx", &bin[i]);
    }
    return bin;
}

int main() {
    const char* hexkeymaterial = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    const char* hexsalt = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

    size_t key_len, salt_len;
    unsigned char* key = hex_to_bin(hexkeymaterial, &key_len);
    unsigned char* salt = hex_to_bin(hexsalt, &salt_len);

    if (key == NULL || salt == NULL) {
        fprintf(stderr, "Invalid hex input\n");
        return 1;
    }

    unsigned char* result;
    unsigned int result_len;

    result = HMAC(EVP_sha256(), salt, salt_len, key, key_len, NULL, &result_len);

    if (result == NULL) {
        fprintf(stderr, "HMAC calculation failed\n");
        free(key);
        free(salt);
        return 1;
    }

    // 输出结果
    for (unsigned int i = 0; i < result_len; i++) {
        printf("%02x", result[i]);
    }
    printf("\n");

    free(key);
    free(salt);
    return 0;
}