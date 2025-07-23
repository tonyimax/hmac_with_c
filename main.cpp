#include <cassert>
#include <cstring>
#include <iomanip>
#include <openssl/sha.h>
#include <iostream>

void hmac_sha256(const unsigned char *key,
                 int key_len,
                 const unsigned char *d,
                 size_t n,
                 unsigned char *md,
                 unsigned int *md_len);

void HMAC_SHA256(const uint8_t *key, size_t keylen, const uint8_t *data, size_t datalen, uint8_t *hmac);

// 辅助函数：打印十六进制
void print_hex(const uint8_t* data, size_t len) {
    std::cout <<"HASH : ";
    for (size_t i = 0; i < len; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(data[i]);
    }
    std::cout << std::dec << std::endl;
}

int main() {
    std::cout << "C HMAC SHA256 TEST: hmac_sha256->" ;
    char *key = "secretKey";
    int key_len = strlen(key);
    char* d = "Hello, HMAC-SM3!";
    int dlen = strlen(d);
    char* md = new char[SHA256_DIGEST_LENGTH]{0};
    unsigned int md_len = SHA256_DIGEST_LENGTH;
    hmac_sha256((unsigned char*)key,key_len,(unsigned char*)d,dlen,(unsigned char*)md,&md_len);

    print_hex(reinterpret_cast<uint8_t*>(md),md_len);

    uint8_t key1[] = "secretKey";
    uint8_t data1[] = "Hello, HMAC-SM3!";
    uint8_t hmac1[SHA256_DIGEST_LENGTH];
    HMAC_SHA256(key1,key_len,data1,dlen,hmac1);
    std::cout << "C HMAC SHA256 TEST: HMAC_SHA256->" ;
    print_hex(hmac1,SHA256_DIGEST_LENGTH);

    return 0;
}

//SHA256_CBLOCK=SHA_LBLOCK*4
//SHA_LBLOCK=16
//SHA256_CBLOCK=16*4=64
//B=64
#define B SHA256_CBLOCK
//SHA256_DIGEST_LENGTH=32
//L=32
#define L (SHA256_DIGEST_LENGTH)
//SHA256_DIGEST_LENGTH=32
//K=64
#define K (SHA256_DIGEST_LENGTH * 2)

//B=64  L=32   K=64

// ipad = the byte 0x36 repeated B times
// opad = the byte 0x5C repeated B times
// I_PAD and O_PAD repeated 64 times
#define I_PAD 0x36
#define O_PAD 0x5C

/*
 * HMAC(H, K) == H(K ^ opad, H(K ^ ipad, text))
 *
 *    H: Hash function (sha256)
 *    K: Secret key
 *    B: Block byte length
 *    L: Byte length of hash function output
 *
 * https://tools.ietf.org/html/rfc2104
 */
void hmac_sha256(const unsigned char *key,
                 int key_len,
                 const unsigned char *d,
                 size_t n,
                 unsigned char *md,
                 unsigned int *md_len)
{
    assert(key);
    assert(d);
    assert(md);

    if (*md_len < SHA256_DIGEST_LENGTH){
        return;
    }

    SHA256_CTX shaCtx;
    uint8_t kh[SHA256_DIGEST_LENGTH];

    /*
     * If the key length is bigger than the buffer size B, apply the hash
     * function to it first and use the result instead.
     */
    //如果密钥大于64字节使用HASH计算，并返回一个32字节长度密钥
    if (key_len > B) {
        SHA256_Init(&shaCtx);
        SHA256_Update(&shaCtx, key, key_len);
        SHA256_Final(kh, &shaCtx);
        key_len = SHA256_DIGEST_LENGTH;
        key = kh;
    }
    //kh为原始密钥大于64，使用HASH算法计算出来的一个32位新密钥

    /*
     * (1) append zeros to the end of K to create a B byte string
     *     (e.g., if K is of length 20 bytes and B=64, then K will be
     *     appended with 44 zero bytes 0x00)
     * (2) XOR (bitwise exclusive-OR) the B byte string computed in step
     *     (1) with ipad
     */
    //如果密钥长度 小于64，在后面填充0x00，然后进行XOR运算
    uint8_t kx[B];//初始化用于保存进行位异域运算后的密钥
    //密钥字节与I_PAD进行位异域运算
    for (size_t i = 0; i < key_len; i++) {
        kx[i] = I_PAD ^ key[i];
    }
    //密钥后面填充0x00与I_PAD进行位异域运算
    for (size_t i = key_len; i < B; i++) {
        kx[i] = I_PAD ^ 0;
    }
    //kx为原始密钥小于64进行填充0x00后，通过异域运算出来的新密钥

    /*
     * (3) append the stream of data 'text' to the B byte string resulting
     *     from step (2)
     * (4) apply H to the stream generated in step (3)
     */
    SHA256_Init(&shaCtx); //初始化64位初始加密变量
    SHA256_Update(&shaCtx, kx, B);
    SHA256_Update(&shaCtx, d, n);
    SHA256_Final(md, &shaCtx);

    /*
     * (5) XOR (bitwise exclusive-OR) the B byte string computed in
     *     step (1) with opad
     *
     * NOTE: The "kx" variable is reused.
     */
    for (size_t i = 0; i < key_len; i++) kx[i] = O_PAD ^ key[i];
    for (size_t i = key_len; i < B; i++) kx[i] = O_PAD ^ 0;

    /*
     * (6) append the H result from step (4) to the B byte string
     *     resulting from step (5)
     * (7) apply H to the stream generated in step (6) and output
     *     the result
     */
    SHA256_Init(&shaCtx);
    SHA256_Update(&shaCtx, kx, B);
    SHA256_Update(&shaCtx, md, SHA256_DIGEST_LENGTH);
    SHA256_Final(md, &shaCtx);

    *md_len = SHA256_DIGEST_LENGTH;
}



#include <stdio.h>
#include <string.h>
#include <stdint.h>
//#include "sha256.h"  // 假设你已经有了SHA-256的实现
#define SHA256_BLOCK_SIZE 64
#define SHA256_DIGEST_SIZE 32
void HMAC_SHA256(const uint8_t *key, size_t keylen, const uint8_t *data, size_t datalen, uint8_t *hmac) {
    uint8_t k_ipad[SHA256_BLOCK_SIZE];  // 用于内填充的数组
    uint8_t k_opad[SHA256_BLOCK_SIZE];  // 用于外填充的数组
    uint8_t key_hash[SHA256_DIGEST_SIZE];  // 用于存储密钥的哈希值
    uint8_t inner_hash[SHA256_DIGEST_SIZE];  // 存储内填充和数据的哈希结果
    size_t i;

    if (keylen > SHA256_BLOCK_SIZE) {
        // 如果密钥长度大于块大小，先对密钥进行哈希处理
        SHA256(key, keylen, key_hash);
        key = key_hash;
        keylen = SHA256_DIGEST_SIZE;
    }

    // 初始化内填充和外填充数组
    memset(k_ipad, 0x36, SHA256_BLOCK_SIZE);
    memset(k_opad, 0x5C, SHA256_BLOCK_SIZE);
    for (i = 0; i < keylen; i++) {
        k_ipad[i] ^= key[i];  // 内填充与密钥进行异或操作
        k_opad[i] ^= key[i];  // 外填充与密钥进行异或操作
    }

    // 计算内填充和数据的哈希值
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, k_ipad, SHA256_BLOCK_SIZE);//与密钥位异域运算后的内填充数据
    SHA256_Update(&ctx, data, datalen);//要进行HAMC运算的原始数据
    SHA256_Final(inner_hash, &ctx);//使用SHA256哈希算法计算出的哈希值

    // 使用外填充和内填充的哈希值再次进行哈希处理得到最终的HMAC值
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, k_opad, SHA256_BLOCK_SIZE);//与密钥位异域运算后的外填充数据
    SHA256_Update(&ctx, inner_hash, SHA256_DIGEST_SIZE);//使用SHA256哈希算法计算出的哈希值数据
    SHA256_Final(hmac, &ctx);//最终输出的HMAC哈希值
}
