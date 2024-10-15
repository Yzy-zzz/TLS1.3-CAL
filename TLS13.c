#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <string.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <gcrypt.h>
#include <arpa/inet.h> 
#include "decrypt-tls-utils.h"
#include <stdbool.h>


// 两个为零的salt和ikm 用sha384生成的early_secret
unsigned char zero_early_secret_sha384[] = {
        0x7e, 0xe8, 0x20, 0x6f, 0x55, 0x70, 0x02, 0x3e,
        0x6d, 0xc7, 0x51, 0x9e, 0xb1, 0x07, 0x3b, 0xc4,
        0xe7, 0x91, 0xad, 0x37, 0xb5, 0xc3, 0x82, 0xaa,
        0x10, 0xba, 0x18, 0xe2, 0x35, 0x7e, 0x71, 0x69,
        0x71, 0xf9, 0x36, 0x2f, 0x2c, 0x2f, 0xe2, 0xa7,
        0x6b, 0xfd, 0x78, 0xdf, 0xec, 0x4e, 0xa9, 0xb5
    };

// 两个为零的salt和ikm 用sha256生成的early_secret
unsigned char zero_early_secret_sha256[] = {
        0x33, 0xad, 0x0a, 0x1c, 0x60, 0x7e, 0xc0, 0x3b,
        0x09, 0xe6, 0xcd, 0x98, 0x93, 0x68, 0x0c, 0xe2,
        0x10, 0xad, 0xf3, 0x00, 0xaa, 0x1f, 0x26, 0x60,
        0xe1, 0xb2, 0x2e, 0x10, 0xf1, 0x70, 0xf9, 0x2a
};

//sha256的empty_hash
unsigned char empty_hash_sha256[] = {
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
    0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
    0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
};

//sha384的empty_hash
unsigned char empty_hash_sha384[] = {
    0x38, 0xb0, 0x60, 0xa7, 0x51, 0xac, 0x96, 0x38,
    0x4c, 0xd9, 0x32, 0x7e, 0xb1, 0xb1, 0xe3, 0x6a,
    0x21, 0xfd, 0xb7, 0x11, 0x14, 0xbe, 0x07, 0x43,
    0x4c, 0x0c, 0xc7, 0xbf, 0x63, 0xf6, 0xe1, 0xda,
    0x27, 0x4e, 0xde, 0xbf, 0xe7, 0x6f, 0x65, 0xfb,
    0xd5, 0x1a, 0xd2, 0xf1, 0x48, 0x98, 0xb9, 0x5b
};



typedef struct {
    unsigned char *data;
    size_t len;
    size_t allocated_len;
} ByteArray;

ByteArray* byte_array_new() {
    ByteArray *array = (ByteArray*)malloc(sizeof(ByteArray));
    array->len = 0;
    array->allocated_len = 16; // 初始分配长度
    array->data = (unsigned char*)malloc(array->allocated_len * sizeof(unsigned char));
    return array;
}

void byte_array_append(ByteArray *array, const unsigned char *data, size_t length) {
    while (array->len + length > array->allocated_len) {
        array->allocated_len *= 2;
        array->data = (unsigned char*)realloc(array->data, array->allocated_len * sizeof(unsigned char));
    }
    memcpy(array->data + array->len, data, length);
    array->len += length;
}


void byte_array_free(ByteArray *array) {
    free(array->data);
    free(array);
}


gcry_error_t
hkdf_expand(int hashalgo, const uint8_t *prk, unsigned prk_len, const uint8_t *info, unsigned info_len,
            uint8_t *out, unsigned out_len)
{
	// Current maximum hash output size: 48 bytes for SHA-384.
	unsigned char	        lastoutput[48];
	gcry_md_hd_t    h;
	gcry_error_t    err;
	const unsigned  hash_len = gcry_md_get_algo_dlen(hashalgo);

	/* Some sanity checks */
	if (!(out_len > 0 && out_len <= 255 * hash_len) ||
	    !(hash_len > 0 && hash_len <= sizeof(lastoutput))) {
		return GPG_ERR_INV_ARG;
	}

	err = gcry_md_open(&h, hashalgo, GCRY_MD_FLAG_HMAC);
	if (err) {
		return err;
	}

	for (unsigned offset = 0; offset < out_len; offset += hash_len) {
		gcry_md_reset(h);
		gcry_md_setkey(h, prk, prk_len);                    /* Set PRK */
		if (offset > 0) {
			gcry_md_write(h, lastoutput, hash_len);     /* T(1..N) */
		}
		gcry_md_write(h, info, info_len);                   /* info */
		gcry_md_putc(h, (uint8_t) (offset / hash_len + 1));  /* constant 0x01..N */

		memcpy(lastoutput, gcry_md_read(h, hashalgo), hash_len);
		memcpy(out + offset, lastoutput, MIN(hash_len, out_len - offset));
	}

	gcry_md_close(h);
	return 0;
}

/*
 * Computes HKDF-Expand-Label(Secret, Label, Hash(context_value), Length) with a
 * custom label prefix. If "context_hash" is NULL, then an empty context is
 * used. Otherwise it must have the same length as the hash algorithm output.
 */
bool tls13_hkdf_expand_label_context(int md, const StringInfo *secret,
                        const char *label_prefix, const char *label,
                        const guint8 *context_hash, guint8 context_length,
                        guint16 out_len, guchar **out)
{
    /* RFC 8446 Section 7.1:
     * HKDF-Expand-Label(Secret, Label, Context, Length) =
     *      HKDF-Expand(Secret, HkdfLabel, Length)
     * struct {
     *     uint16 length = Length;
     *     opaque label<7..255> = "tls13 " + Label; // "tls13 " is label prefix.
     *     opaque context<0..255> = Context;
     * } HkdfLabel;
     *
     * RFC 5869 HMAC-based Extract-and-Expand Key Derivation Function (HKDF):
     * HKDF-Expand(PRK, info, L) -> OKM
     */
    gcry_error_t err;
    const guint label_prefix_length = (guint) strlen(label_prefix);
    const guint label_length = (guint) strlen(label);

    /* Some sanity checks */
    // DISSECTOR_ASSERT(label_length > 0 && label_prefix_length + label_length <= 255);

    /* info = HkdfLabel { length, label, context } */
    ByteArray *info = byte_array_new();
    const guint16 length = htons(out_len);
    byte_array_append(info, (const guint8 *)&length, sizeof(length));

    const guint8 label_vector_length = label_prefix_length + label_length;
    byte_array_append(info, &label_vector_length, 1);
    byte_array_append(info, (const guint8 *)label_prefix, label_prefix_length);
    byte_array_append(info, (const guint8*)label, label_length);

    byte_array_append(info, &context_length, 1);
    if (context_length) {
        byte_array_append(info, context_hash, context_length);
    }

    // *out = (guchar *)wmem_alloc(NULL, out_len);
    *out = (guchar *)malloc(out_len);
    err = hkdf_expand(md, secret->data, secret->data_len, info->data, info->len, *out, out_len);
    byte_array_free(info);

    if (err) {
        // ssl_debug_printf("%s failed  %d: %s\n", G_STRFUNC, md, gcry_strerror(err));
        //释放
        free(*out);
        *out = NULL;
        return false;
    }

    return true;
}


bool tls13_hkdf_expand_label(int md, const StringInfo *secret,
                        const char *label_prefix, const char *label,
                        guint16 out_len, unsigned char **out)
{
    return tls13_hkdf_expand_label_context(md, secret, label_prefix, label, NULL, 0, out_len, out);
}



// // Function to calculate the Transcript-Hash (SHA-256 in this case)
// void transcript_hash(const unsigned char *messages, size_t messages_len, unsigned char *hash_output)
// {
//     EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
//     EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
//     EVP_DigestUpdate(mdctx, messages, messages_len);
//     EVP_DigestFinal_ex(mdctx, hash_output, NULL);
//     EVP_MD_CTX_free(mdctx);
// }

// // Function to perform HKDF-Expand-Label
// void hkdf_expand_label(const unsigned char *secret, size_t secret_len,
//                        const char *label, const unsigned char *context, size_t context_len,
//                        unsigned char *output, size_t output_len)
// {
//     // Define the label prefix as per TLS 1.3: "tls13 "
//     const char *label_prefix = "tls13 ";
//     size_t label_prefix_len = strlen(label_prefix);
//     size_t label_len = strlen(label);

//     // Concatenate label_prefix + label
//     size_t hkdf_label_len = label_prefix_len + label_len;
//     unsigned char hkdf_label[512];
//     memcpy(hkdf_label, label_prefix, label_prefix_len);
//     memcpy(hkdf_label + label_prefix_len, label, label_len);

//     // Create HKDF-Label structure
//     unsigned char hkdf_label_structure[256];
//     size_t pos = 0;
//     hkdf_label_structure[pos++] = (output_len >> 8) & 0xff; // Length of output (2 bytes)
//     hkdf_label_structure[pos++] = output_len & 0xff;
//     hkdf_label_structure[pos++] = hkdf_label_len; // Length of label
//     memcpy(hkdf_label_structure + pos, hkdf_label, hkdf_label_len);
//     pos += hkdf_label_len;
//     hkdf_label_structure[pos++] = context_len; // Length of context
//     memcpy(hkdf_label_structure + pos, context, context_len);
//     pos += context_len;

//     // Perform HKDF-Expand
//     HMAC(EVP_sha256(), secret, secret_len,
//          hkdf_label_structure, pos, output, NULL);
// }

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

// x25519密钥交换算法,输入client_private,server_public,输出shared_secret
unsigned char *derive_shared_secret(const unsigned char *client_private, const unsigned char *server_public, size_t *shared_secret_len)
{
    // 以十六进制打印客户端私钥
    printf("Client private key: ");
    for (int i = 0; i < 32; i++)
    {
        printf("%02x", client_private[i]);
    }
    printf("\n");

    // 以十六进制打印服务端公钥
    printf("Server public key: ");
    for (int i = 0; i < 32; i++)
    {
        printf("%02x", server_public[i]);
    }
    printf("\n");

    // // 创建一个上下文来执行X25519操作
    // EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    // if (!pctx) handleErrors();

    // 初始化客户端的私钥
    EVP_PKEY *client_pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, client_private, 32);
    if (!client_pkey)
        handleErrors();

    // 初始化服务器的公钥
    EVP_PKEY *server_pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, server_public, 32);
    if (!server_pkey)
        handleErrors();

    // 创建一个新的上下文来执行派生操作
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(client_pkey, NULL);
    if (!ctx)
        handleErrors();

    if (EVP_PKEY_derive_init(ctx) <= 0)
        handleErrors();

    // 设置对方的公钥
    if (EVP_PKEY_derive_set_peer(ctx, server_pkey) <= 0)
        handleErrors();

    // 计算派生密钥的长度
    if (EVP_PKEY_derive(ctx, NULL, shared_secret_len) <= 0)
        handleErrors();

    // 分配内存用于存储派生的共享密钥
    unsigned char *shared_secret = (unsigned char *)OPENSSL_malloc(*shared_secret_len);
    if (!shared_secret)
        handleErrors();

    // 派生共享密钥
    if (EVP_PKEY_derive(ctx, shared_secret, shared_secret_len) <= 0)
        handleErrors();
    
    // 以十六进制打印共享密钥   
    printf("x25519 Shared secret: ");
    for (int i = 0; i < *shared_secret_len; i++)
    {
        printf("%02x", shared_secret[i]);
    }
    printf("\n");

    // 清理资源
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(client_pkey);
    EVP_PKEY_free(server_pkey);

    return shared_secret;
}



int main()
{
    // TLS1.3使用的密码套件是TLS_AES_128_GCM_SHA256

    // // 初始化client_private
    // unsigned char client_private[32] = {
    //     0xce, 0xf1, 0x55, 0x00, 0xeb, 0x21, 0x04, 0xa5,
    //     0xcc, 0xe6, 0x87, 0x87, 0xa7, 0x85, 0x3c, 0x7c,
    //     0xbe, 0x43, 0xfc, 0x26, 0x07, 0x48, 0xdc, 0x86,
    //     0xa9, 0xb6, 0x97, 0xe4, 0x45, 0x24, 0x80, 0xe5};
    // // 初始化server_public
    // unsigned char server_public[32] = {
    //     0xbd, 0xc2, 0x3f, 0x37, 0xec, 0xc5, 0xc7,
    //     0x67, 0x1, 0xf0, 0x80, 0xe8, 0xc5, 0xa7, 0xe, 0x1f,
    //     0xa5, 0x29, 0xec, 0xa, 0x5, 0xab, 0x70, 0xcd, 0x2f,
    //     0xcc, 0x2b, 0x78, 0x10, 0xd9, 0xe2, 0x59};

    unsigned char client_private[] = {
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f
    };

    unsigned char server_public[] = {
        0x9f, 0xd7, 0xad, 0x6d, 0xcf, 0xf4, 0x29, 0x8d,
        0xd3, 0xf9, 0x6d, 0x5b, 0x1b, 0x2a, 0xf9, 0x10,
        0xa0, 0x53, 0x5b, 0x14, 0x88, 0xd7, 0xf8, 0xfa,
        0xbb, 0x34, 0x9a, 0x98, 0x28, 0x80, 0xb6, 0x15
    };


    // 生成shared_secret
    size_t shared_secret_len = 32;
    unsigned char *shared_secret = derive_shared_secret(client_private, server_public, &shared_secret_len);


    StringInfo *secret = (StringInfo *)malloc(sizeof(StringInfo));
    secret->data = zero_early_secret_sha384;
    secret->data_len = 48;

    StringInfo *empty_hash = (StringInfo *)malloc(sizeof(StringInfo));
    empty_hash->data = empty_hash_sha384;
    empty_hash->data_len = 48;

    unsigned char *hand_shared_secret ;

    const char *hash_name = "SHA384";
    int hash_algo = gcry_md_map_name(hash_name);

    tls13_hkdf_expand_label_context(hash_algo, secret, "tls13 ", "derived", empty_hash->data, empty_hash->data_len, 48, &hand_shared_secret);
    //输出hand_shared_secret
    printf("hand_shared_secret: ");
    for (int i = 0; i < 48; i++)
    {
        printf("%02x", hand_shared_secret[i]);
    }
    printf("\n");


    // unsigned char messages[] = {0x1, 0x0, 0x6, 0xcd, 0x3, 0x3, 0x67, 0xc, 0xc7, 0xde, 0xd5,
    //                          0x57, 0x23, 0x2f, 0x12, 0xc6, 0x6e, 0x38, 0x5f, 0x18, 0xd9, 0x88, 0x8b, 0x58, 0x83, 0xcc, 0x82, 0x2e, 0x92, 0xc7, 0x22, 0xd6, 0x80, 0x0, 0x49, 0x63,
    //                          0x85, 0x60, 0x20, 0x4f, 0xca, 0xa7, 0xc3, 0x27, 0x7, 0x8, 0xcd, 0xb0, 0x3d, 0x9f, 0x21, 0x2e, 0x4d, 0xe4, 0x7f, 0xb3, 0x0, 0x4f, 0x2c, 0x6a, 0x35, 0xf9,
    //                          0x22, 0xde, 0x87, 0x2e, 0xac, 0xa7, 0xc7, 0x25, 0x2, 0x0, 0x18, 0xa, 0xa, 0x13, 0x1, 0x13, 0x2, 0x13, 0x3, 0xc0, 0x2b, 0xc0, 0x2f, 0xc0, 0x2c, 0xc0, 0x30,
    //                          0xcc, 0xa9, 0xcc, 0xa8, 0xc0, 0x13, 0xc0, 0x14, 0x1, 0x0, 0x6, 0x6c, 0x1a, 0x1a, 0x0, 0x0, 0xfe, 0xd, 0x0, 0xda, 0x0, 0x0, 0x1, 0x0, 0x1, 0x73, 0x0, 0x20,
    //                          0x14, 0xca, 0x9e, 0x4d, 0x38, 0x7b, 0xcc, 0xf3, 0x57, 0x46, 0xe0, 0x40, 0x7d, 0xaa, 0xac, 0xc6, 0xb2, 0x8a, 0x4f, 0x84, 0x45, 0xef, 0x5a, 0x51, 0x58, 0x89,
    //                          0x4d, 0xb9, 0x83, 0xe2, 0x40, 0x70, 0x0, 0xb0, 0xac, 0x62, 0xcb, 0x6f, 0x92, 0xb, 0xa3, 0xce, 0x52, 0xcd, 0xd9, 0x6a, 0xdc, 0xba, 0x41, 0xb7, 0xd8, 0xe9, 0x46,
    //                          0x57, 0x94, 0xe6, 0x67, 0xe5, 0x46, 0x8a, 0xde, 0x93, 0x25, 0xa8, 0x85, 0xa1, 0x3a, 0x77, 0xdc, 0x83, 0xbc, 0xc5, 0x95, 0x35, 0x9b, 0xeb, 0xfe, 0x18, 0x0, 0x26,
    //                          0x50, 0xb8, 0xd2, 0x60, 0x2c, 0x95, 0x65, 0xcc, 0x7d, 0xd9, 0x81, 0x4b, 0x5, 0x5f, 0x1e, 0x3a, 0x5c, 0x31, 0xc, 0x66, 0x90, 0x1e, 0xb3, 0x2b, 0x67, 0x41, 0x4a,
    //                          0xe8, 0x49, 0x89, 0xd1, 0xfa, 0x2c, 0x6, 0x73, 0x2, 0x43, 0xe9, 0x47, 0x20, 0xbd, 0xa, 0x78, 0x4f, 0x81, 0xe7, 0x80, 0x71, 0x8f, 0xf3, 0x38, 0xb0, 0x3e, 0xd5,
    //                          0x61, 0xf7, 0x94, 0xf3, 0x1, 0x78, 0x76, 0x32, 0xff, 0x14, 0xb8, 0x37, 0x35, 0x71, 0x56, 0xcf, 0xf3, 0x9, 0x46, 0xb6, 0x7e, 0xbb, 0x4a, 0xdc, 0xae, 0x4b, 0xf5,
    //                          0x43, 0x8f, 0xc8, 0x32, 0xb3, 0x34, 0x1d, 0x2b, 0x6b, 0x2, 0x9d, 0xda, 0x94, 0x6c, 0x23, 0x1d, 0x97, 0xda, 0x2d, 0xd8, 0x47, 0xb9, 0x26, 0x20, 0x59, 0xdd, 0x69,
    //                          0x4, 0x86, 0x20, 0xf7, 0xc4, 0xb4, 0x1, 0xbb, 0xb, 0x72, 0x87, 0xd5, 0x32, 0xca, 0xd4, 0xfa, 0xc8, 0xd4, 0x59, 0x34, 0x22, 0x5d, 0x0, 0x2d, 0x0, 0x2, 0x1, 0x1,
    //                          0x0, 0x1b, 0x0, 0x3, 0x2, 0x0, 0x2, 0x0, 0xb, 0x0, 0x2, 0x1, 0x0, 0xff, 0x1, 0x0, 0x1, 0x0, 0x0, 0xd, 0x0, 0x12, 0x0, 0x10, 0x4, 0x3, 0x8, 0x4, 0x4, 0x1, 0x5, 0x3,
    //                          0x8, 0x5, 0x5, 0x1, 0x8, 0x6, 0x6, 0x1, 0x0, 0x12, 0x0, 0x0, 0x0, 0xa, 0x0, 0xc, 0x0, 0xa, 0xaa, 0xaa, 0x63, 0x99, 0x0, 0x1d, 0x0, 0x17, 0x0, 0x18, 0x0, 0x17, 0x0,
    //                          0x0, 0x0, 0x23, 0x0, 0x0, 0x0, 0x33, 0x4, 0xef, 0x4, 0xed, 0xaa, 0xaa, 0x0, 0x1, 0x0, 0x63, 0x99, 0x4, 0xc0, 0xe3, 0x71, 0x2d, 0x85, 0x1a, 0xe, 0x5d, 0x79, 0xb8, 0x31,
    //                          0xc5, 0xe3, 0x4a, 0xb2, 0x2b, 0x41, 0xa1, 0x98, 0x17, 0x1d, 0xe2, 0x9, 0xb8, 0xb8, 0xfa, 0xca, 0x23, 0xa1, 0x1c, 0x62, 0x48, 0x59, 0x93, 0x9a, 0x1d, 0x11, 0x8a, 0x16, 0xd0,
    //                          0x4c, 0xb8, 0x91, 0x97, 0xb7, 0x1f, 0x9a, 0x25, 0x60, 0x10, 0x50, 0x86, 0x9a, 0x1f, 0x21, 0xd9, 0x2c, 0xb7, 0xb5, 0xb1, 0xaf, 0xdc, 0x95, 0xb8, 0x82, 0x52, 0x21, 0x5b, 0x58,
    //                          0x1b, 0x16, 0xcf, 0x96, 0xe7, 0x91, 0x2a, 0x18, 0x68, 0xb8, 0x41, 0x20, 0xe0, 0x4a, 0x22, 0x83, 0xc7, 0x82, 0x1e, 0x21, 0x17, 0xc7, 0x33, 0x69, 0xae, 0x7c, 0x70, 0xeb, 0xc4,
    //                          0x15, 0x5, 0x72, 0x32, 0xcf, 0x9c, 0x17, 0xde, 0x63, 0x38, 0x3f, 0xc6, 0x6, 0x74, 0xc5, 0x23, 0xb9, 0xa8, 0x7, 0x25, 0x35, 0x85, 0xcf, 0x11, 0xb8, 0x61, 0x30, 0x47, 0x97, 0x10,
    //                          0x11, 0x6, 0x82, 0x56, 0xc9, 0xe1, 0x92, 0xee, 0x14, 0xa1, 0xac, 0x8b, 0x51, 0x1a, 0xa, 0xc8, 0xad, 0x9b, 0x76, 0x41, 0xb5, 0x1, 0xab, 0xd2, 0xb7, 0xc5, 0xb5, 0x20, 0x81, 0xe8,
    //                          0x5d, 0xaf, 0x31, 0x44, 0xb4, 0x5, 0x21, 0x7e, 0x7a, 0xaa, 0x11, 0xb3, 0x60, 0x2a, 0xbb, 0x4, 0xea, 0xa4, 0x81, 0x36, 0xf7, 0x32, 0xee, 0x60, 0x7a, 0xd7, 0x1a, 0x9e, 0x73, 0x7c,
    //                          0xc, 0xa5, 0xc9, 0x41, 0x9f, 0x1, 0x88, 0x83, 0x8c, 0x57, 0x22, 0x40, 0xc9, 0x11, 0x55, 0xa, 0x86, 0xb6, 0x69, 0x52, 0x5b, 0x91, 0xf1, 0xda, 0xf, 0xe, 0xc9, 0x4f, 0x6c, 0xd7, 0x5d,
    //                          0xd4, 0x33, 0x98, 0x41, 0xbb, 0x50, 0xa6, 0x11, 0x12, 0xe7, 0x73, 0xbd, 0xa5, 0x36, 0xc1, 0x6f, 0x90, 0x7b, 0xbc, 0x14, 0x59, 0x89, 0xa7, 0x7f, 0x91, 0xf6, 0x3a, 0xa3, 0x60, 0x9d,
    //                          0x44, 0x1c, 0x7f, 0x28, 0xe4, 0x5d, 0xd9, 0x3c, 0x9e, 0xca, 0xa3, 0x71, 0xe9, 0x99, 0x59, 0x87, 0x56, 0x94, 0x32, 0x22, 0x2, 0x91, 0x55, 0x81, 0xe5, 0x13, 0x3b, 0x2d, 0xf4, 0xbd, 0xcb,
    //                          0xeb, 0x2, 0x4a, 0x25, 0x6a, 0xd5, 0xd9, 0xa7, 0x17, 0xa7, 0x50, 0xd0, 0xd0, 0xcf, 0xd1, 0x5b, 0xa, 0x8d, 0x3, 0x7c, 0xc6, 0x23, 0x70, 0xa0, 0x83, 0xa8, 0xd8, 0x56, 0x5d, 0x2, 0x15,
    //                          0x6c, 0xa7, 0xb, 0x5, 0x18, 0x7c, 0x3e, 0xe, 0xf8, 0x5e, 0xb9, 0x27, 0x4d, 0x56, 0x33, 0x41, 0xcc, 0x29, 0xb7, 0x6e, 0x38, 0x0, 0x71, 0x1c, 0x5a, 0x37, 0xc8, 0x8b, 0x63, 0x5a, 0x24,
    //                          0xc4, 0x8c, 0x8, 0xe5, 0xfc, 0xb6, 0x36, 0x22, 0x6f, 0x8, 0x9, 0xcf, 0x73, 0xe0, 0x4a, 0xb0, 0x93, 0xc, 0x1d, 0xa4, 0x38, 0x6b, 0x7a, 0xa, 0xc7, 0x5b, 0x87, 0x6b, 0xf0, 0xb6, 0x3c,
    //                          0x99, 0x37, 0xb3, 0x55, 0x57, 0xb1, 0xaa, 0x58, 0xb, 0xc, 0x85, 0x5e, 0x13, 0x77, 0x25, 0x47, 0x1d, 0xeb, 0x2a, 0x4f, 0xf, 0xc0, 0x92, 0xcc, 0xb7, 0x97, 0x37, 0xe8, 0x96, 0xe3, 0xb5,
    //                          0x0, 0xc0, 0x77, 0x52, 0xca, 0xb8, 0x7a, 0x71, 0x9, 0x8e, 0x6, 0x93, 0x2c, 0xc2, 0x99, 0xc7, 0xa4, 0x4b, 0x2d, 0x7d, 0x43, 0xa5, 0x7c, 0xc8, 0xc1, 0x74, 0xc2, 0xc6, 0x8f, 0x61, 0x58,
    //                          0x7e, 0x6a, 0x8e, 0x6b, 0xa5, 0x75, 0x2f, 0x1a, 0x28, 0x36, 0x47, 0x52, 0xa6, 0xe6, 0x3d, 0xae, 0x5a, 0x35, 0xf1, 0xd5, 0x97, 0x86, 0x10, 0x4d, 0xa3, 0x64, 0x3, 0x95, 0xe2, 0x66,
    //                          0xda, 0xa5, 0xb2, 0x5e, 0xfa, 0x79, 0xd2, 0xe9, 0xc6, 0xfe, 0x76, 0x44, 0xc3, 0x45, 0x42, 0xc3, 0x70, 0x44, 0xa8, 0xb8, 0x5f, 0xa, 0xf1, 0x35, 0x67, 0x0, 0xa2, 0x13, 0xe1, 0x1e,
    //                          0xcd, 0x81, 0x1, 0x43, 0x28, 0x22, 0x54, 0xa6, 0x3a, 0xd6, 0xf8, 0xb6, 0x0, 0x94, 0x97, 0xae, 0xd1, 0x57, 0xd1, 0x5, 0x62, 0xfc, 0x28, 0x6a, 0x37, 0x92, 0x6d, 0x75, 0xda, 0x9d, 0xe5,
    //                          0x90, 0xa7, 0xfe, 0x63, 0x77, 0x2c, 0x14, 0xcd, 0xcb, 0x40, 0x27, 0xcc, 0xd6, 0x55, 0xb3, 0x43, 0x4a, 0x37, 0x95, 0x76, 0xc6, 0xd1, 0x37, 0xb, 0x0, 0x13,
    //                          0x3f, 0x3c, 0x7c, 0xeb, 0x69, 0x4d, 0x93, 0x89, 0xb1, 0x9e, 0x4b, 0x1b, 0xb7, 0xea, 0x2e, 0xd2, 0xd4, 0xab, 0x70, 0x17, 0x9d, 0xa9, 0x53, 0x38, 0x58, 0x86,
    //                          0xcd, 0x3f, 0x31, 0xc0, 0xd7, 0x30, 0x22, 0xaf, 0x32, 0x6b, 0x81, 0xb7, 0xa1, 0xab, 0xc3, 0x6d, 0xad, 0xa, 0x17, 0xf6, 0x45, 0x1f, 0xa3, 0x50, 0xb4, 0x26, 0x10, 0xae, 0x29, 0x29,
    //                          0x1a, 0xfa, 0x56, 0xae, 0x10, 0xda, 0x92, 0x24, 0x65, 0x85, 0xec, 0xf8, 0x11, 0x43, 0x9b, 0xd, 0xca, 0xc5, 0xce, 0xdd, 0x42, 0xa9, 0x8d, 0xf7, 0x73, 0xf7, 0x97, 0x94, 0xb7, 0x33,
    //                          0x3b, 0x38, 0xbb, 0x2a, 0xf, 0x64, 0x5f, 0xcb, 0xe2, 0x9e, 0x4, 0xa5, 0x42, 0xf4, 0xa7, 0x5c, 0x4d, 0xba, 0x84, 0xdc, 0x74, 0x8b, 0x52, 0x9b, 0x46, 0x84, 0x6c, 0xb2, 0x5, 0xd5, 0xb9,
    //                          0x4b, 0xe8, 0x22, 0xb2, 0x4c, 0xc, 0xf3, 0x17, 0xa4, 0x8c, 0x41, 0x69, 0x86, 0xe9, 0x18, 0x6b, 0x89, 0x8d, 0xbb, 0x37, 0x72, 0x31, 0xc2, 0x5d, 0x3a, 0x20, 0x87, 0x5f, 0x64, 0x2b, 0xb2,
    //                          0x35, 0xb, 0xa0, 0xfc, 0x39, 0xcc, 0x81, 0x9e, 0x5a, 0xb1, 0x96, 0x39, 0x5a, 0x40, 0x14, 0x44, 0xc, 0xf3, 0x68, 0x5b, 0x95, 0xa9, 0x6, 0xa6, 0x84, 0x8b, 0x73, 0xa5, 0x13, 0xf3, 0x39, 0xb8, 0x3c,
    //                          0xf7, 0x8d, 0x71, 0xd5, 0x83, 0xaf, 0x6, 0x3e, 0x9, 0xc9, 0xc9, 0x8f, 0x9a, 0x77, 0xd5, 0x7, 0x78, 0x3d, 0x66, 0xa0, 0x28, 0x37, 0x1c, 0xea, 0xe2, 0x88, 0xf, 0x73, 0x87, 0x81, 0xab, 0x74, 0x59,
    //                          0xaa, 0x91, 0xeb, 0xfa, 0x17, 0x7, 0xd2, 0x5c, 0x99, 0x43, 0x1b, 0x41, 0x37, 0xc1, 0xce, 0xaa, 0x6c, 0xbb, 0xd4, 0x7f, 0x93, 0x71, 0x51, 0xf7, 0x16, 0x33, 0x75, 0xc9, 0x78, 0xb5, 0x6c, 0x6e, 0x8a,
    //                          0xb3, 0x13, 0xb3, 0xcc, 0x6e, 0x8e, 0xc0, 0x90, 0xfe, 0x8a, 0xa5, 0xd, 0x60, 0x67, 0x49, 0xdb, 0x27, 0xe3, 0x1c, 0x76, 0x1d, 0x51, 0x2b, 0x87, 0xa7, 0x38, 0x75, 0xc0, 0x6d, 0xbc, 0xb, 0x1f, 0x15, 0xbc,
    //                          0x1c, 0x6b, 0xf0, 0x24, 0x41, 0xc0, 0x2e, 0xd, 0x35, 0x3c, 0x49, 0x47, 0x82, 0x13, 0xb4, 0x2e, 0xa4, 0xa7, 0x9a, 0xca, 0xc0, 0xa9, 0x72, 0x90, 0x9d, 0xaf, 0x9b, 0x1d, 0x6, 0x53, 0x39, 0x77, 0xc5, 0x8f,
    //                          0xbf, 0xa9, 0x51, 0xb2, 0x6b, 0xad, 0xf9, 0x71, 0xae, 0x76, 0x38, 0x5a, 0x95, 0xf0, 0x95, 0xc3, 0x30, 0xb1, 0xb4, 0x57, 0x25, 0x7f, 0x77, 0x1d, 0x3c, 0xbc, 0x2b, 0x75, 0xa9, 0x2b, 0xf9, 0xcc, 0x2f, 0x54,
    //                          0x35, 0x81, 0xf0, 0xb9, 0x92, 0x78, 0x61, 0x4, 0x37, 0x45, 0x89, 0x1d, 0x1c, 0x76, 0x3, 0x7c, 0x51, 0x2d, 0x98, 0x3, 0xd9, 0x59, 0xcb, 0xae, 0xb, 0xc0, 0xab, 0x95, 0x59, 0xe6, 0xcb, 0x82, 0x6f, 0x12, 0x54, 0x54, 0x7b, 0x3a, 0xe3, 0x54, 0x23, 0xfa, 0xf0, 0xb7, 0xde, 0x9b, 0x3c, 0xf0, 0xf5, 0xb1, 0x19, 0x5b, 0x90, 
    //                          0xa7, 0xa, 0x11, 0x59, 0x68, 0x13, 0x3, 0x95, 0xbe, 0x3c, 0x54, 0x75, 0xfd, 0xe7, 0x65, 0x7d, 0xec, 0xa4, 0x27, 0x71, 0x14, 0x60, 0x9, 0x9, 0xb1, 0x22, 0xb, 0xb8, 0xb6, 0x16, 0xb7, 0x1, 0x46, 0xb4, 0xc2, 0xd, 0x0, 0x5d, 0x25, 0x44, 0x2a, 0x27, 0x22, 0x10, 0x96, 0xc9, 0x28, 0x8f, 0x87, 0xec, 0x8e, 0x31, 0x62, 0x1a, 0x6b, 0x5c, 0x50, 
    //                          0x4, 0x11, 0xae, 0xba, 0x15, 0xa6, 0x64, 0xa8, 0x31, 0x2f, 0x16, 0x3c, 0x7e, 0x38, 0x0, 0x8b, 0x10, 0xc1, 0xc1, 0xa8, 0xb, 0x2d, 0x82, 
    //                          0xa9, 0xfe, 0x55, 0x91, 0x70, 0xcb, 0xaa, 0x42, 0x75, 0x67, 0x26, 0xb0, 0xb7, 0xd6, 0xf0, 0xb4, 0x78, 0xac, 0x7d, 0x81, 0xc8, 0xb4, 0x1f, 0xa6, 0x9a, 0x27, 0xe1, 0xb5, 0x7c, 0x2b, 0xbc, 0xdd, 0x31, 0x9a, 0x15, 0x70, 0xa4, 0x62, 0x24, 0xc4, 0x98, 0x73, 0x6c, 0x56, 0x7b, 0x5d, 0xdf, 0x20, 0x27, 0xf0, 0x94, 0x37, 0x50, 0x7b, 0x9a, 0x16, 0xe0, 
    //                          0x9f, 0x60, 0xd2, 0x79, 0xef, 0x17, 0xb3, 0x91, 0x58, 0x78, 0x23, 0x10, 0x19, 0x51, 0x4, 0x81, 0x72, 0xe7, 0x42, 0x7f, 0x82, 0x7e, 0xe3, 0x3a, 0x26, 0x1f, 0x50, 0x68, 0x1, 0xe8, 0x23, 0x4f, 0x9a, 0x27, 0xf4, 0xb7, 0x5a, 
    //                          0x3f, 0x98, 0x37, 0x0, 0xf9, 0xf, 0x1b, 0x34, 0x3b, 0xf8, 0x50, 0x34, 0x70, 0xe1, 0x87, 0x9e, 0x71, 0x70, 0x2b, 0xca, 0x64, 0xb9, 0x2, 0x6, 0x4d, 0x32, 0x1f, 0x7, 0xf1, 0x52, 0x14, 0x8a, 
    //                          0x6a, 0x44, 0x32, 0x6b, 0x8e, 0x1, 0xa1, 0x52, 0x51, 0x42, 0x2f, 0x7, 0x8e, 0x95, 0xf4, 0xa, 0xa, 0xa7, 0x64, 0x54, 0xc0, 0xc1, 0x1b, 0x62, 0x99, 0xe2, 0xdb, 0x29, 0x7c, 0x1, 0xcc, 
    //                          0x46, 0x8d, 0x67, 0x9a, 0x1c, 0x9d, 0x53, 0xcb, 0x5d, 0x5c, 0xb9, 0x81, 0xe8, 0x91, 0x91, 0xa5, 0xc5, 0xaa, 0x2c, 0x2e, 0x7a, 0x1, 0x88, 0x37, 0x20, 0x1e, 0x0, 0x1d, 0x0, 0x20, 0xef, 
    //                          0x7a, 0x6b, 0xd, 0x3b, 0xce, 0x94, 0x2b, 0x5f, 0x52, 0xc1, 0xa6, 0x72, 0x86, 0x51, 0x1a, 0x3, 0x78, 0x80, 0xde, 0x8c, 0x33, 0xc2, 0xf4, 0x3, 0x54, 0x2d, 0xd3, 0xbe,
    //                          0xe7, 0x2, 0x4d, 0x44, 0x69, 0x0, 0x5, 0x0, 0x3, 0x2, 0x68, 0x32, 0x0, 0x2b, 0x0, 0x7, 0x6, 0x5a, 0x5a, 0x3, 0x4, 0x3, 0x3, 0x0, 0x5, 0x0, 0x5, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    //                          0x0, 0x15, 0x0, 0x13, 0x0, 0x0, 0x10, 0x7a, 0x68, 0x2e, 0x77, 0x69, 0x6b, 0x69, 0x70, 0x65, 0x64, 0x69, 0x61, 0x2e, 0x6f, 0x72, 0x67, 0x0, 0x10, 0x0, 0xe, 0x0, 0xc, 0x2, 0x68, 0x32,
    //                          0x8, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31, 0xca, 0xca, 0x0, 0x1, 0x0,
                
    //                         0x2, 0x0, 0x0, 0x76, 0x3, 0x3, 0x7e, 0x39, 0x7c, 0xf1, 0x28, 0x93, 0xc1, 0x68, 0xea, 0x2c, 0xcc,
    //                          0xa1, 0x27, 0xca, 0x86, 0xc7, 0xc3, 0xac, 0xc9, 0xa8, 0x63, 0x14, 0xc2, 0xe, 0x2, 0xb3, 0xb, 0x8f, 0x4b, 0xae, 0x7d, 0x8f, 0x20, 
    //                          0x4f, 0xca, 0xa7, 0xc3, 0x27, 0x7, 0x8, 0xcd, 0xb0, 0x3d, 0x9f, 0x21, 0x2e, 0x4d, 0xe4, 0x7f, 0xb3, 0x0, 0x4f, 0x2c, 0x6a, 0x35, 0xf9,
    //                           0x22, 0xde, 0x87, 0x2e, 0xac, 0xa7, 0xc7, 0x25, 0x2, 0x13, 0x1, 0x0, 0x0, 0x2e, 0x0, 0x2b, 0x0, 0x2, 0x3, 0x4, 0x0, 0x33, 0x0, 0x24, 0x0, 
    //                           0x1d, 0x0, 0x20, 0xbd, 0xc2, 0x3f, 0x37, 0xec, 0xc5, 0xc7, 0x67, 0x1, 0xf0, 0x80, 0xe8, 0xc5, 0xa7, 0xe, 0x1f, 0xa5, 0x29, 0xec, 0xa, 0x5, 0xab,
    //                            0x70, 0xcd, 0x2f, 0xcc, 0x2b, 0x78, 0x10, 0xd9, 0xe2, 0x59

    //                          };


    return 0;
}
