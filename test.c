#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/blake2.h>
#include <openssl/whrlpool.h>
#include <openssl/ripemd.h>
#include <openssl/xxhash.h>

#define MB 1048576
#define GB 1073741824

// Function to generate dumb files of specified size
void generateFile(const char *filename, size_t size) {
    FILE *file = fopen(filename, "wb");
    if (!file) {
        perror("Error creating file");
        exit(EXIT_FAILURE);
    }
    
    char *buffer = (char *)malloc(size);
    if (!buffer) {
        perror("Memory allocation error");
        fclose(file);
        exit(EXIT_FAILURE);
    }
    
    fwrite(buffer, 1, size, file);
    fclose(file);
    free(buffer);
}

// Function to compute hash using MD5
void computeMD5(const char *filename) {
    unsigned char hash[MD5_DIGEST_LENGTH];
    MD5_CTX md5Context;
    MD5_Init(&md5Context);
    
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Error opening file");
        exit(EXIT_FAILURE);
    }
    
    unsigned char data[1024];
    size_t bytesRead;
    while ((bytesRead = fread(data, 1, sizeof(data), file)) != 0) {
        MD5_Update(&md5Context, data, bytesRead);
    }
    MD5_Final(hash, &md5Context);
    
    fclose(file);
}

// Function to compute hash using SHA-1
void computeSHA1(const char *filename) {
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA_CTX sha1Context;
    SHA1_Init(&sha1Context);
    
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Error opening file");
        exit(EXIT_FAILURE);
    }
    
    unsigned char data[1024];
    size_t bytesRead;
    while ((bytesRead = fread(data, 1, sizeof(data), file)) != 0) {
        SHA1_Update(&sha1Context, data, bytesRead);
    }
    SHA1_Final(hash, &sha1Context);
    
    fclose(file);
}

// Function to compute hash using SHA-256
void computeSHA256(const char *filename) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256Context;
    SHA256_Init(&sha256Context);
    
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Error opening file");
        exit(EXIT_FAILURE);
    }
    
    unsigned char data[1024];
    size_t bytesRead;
    while ((bytesRead = fread(data, 1, sizeof(data), file)) != 0) {
        SHA256_Update(&sha256Context, data, bytesRead);
    }
    SHA256_Final(hash, &sha256Context);
    
    fclose(file);
}

// Function to compute hash using SHA-512
void computeSHA512(const char *filename) {
    unsigned char hash[SHA512_DIGEST_LENGTH];
    SHA512_CTX sha512Context;
    SHA512_Init(&sha512Context);
    
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Error opening file");
        exit(EXIT_FAILURE);
    }
    
    unsigned char data[1024];
    size_t bytesRead;
    while ((bytesRead = fread(data, 1, sizeof(data), file)) != 0) {
        SHA512_Update(&sha512Context, data, bytesRead);
    }
    SHA512_Final(hash, &sha512Context);
    
    fclose(file);
}

// Function to compute hash using SHA-3
void computeSHA3(const char *filename) {
    // SHA-3 is not available in OpenSSL
    printf("SHA-3 is not available in OpenSSL.\n");
}

// Function to compute hash using BLAKE2
void computeBLAKE2(const char *filename) {
    unsigned char hash[BLAKE2B_DIGEST_LENGTH];
    BLAKE2B_CTX blake2bContext;
    BLAKE2B_Init(&blake2bContext, BLAKE2B_OUTBYTES);
    
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Error opening file");
        exit(EXIT_FAILURE);
    }
    
    unsigned char data[1024];
    size_t bytesRead;
    while ((bytesRead = fread(data, 1, sizeof(data), file)) != 0) {
        BLAKE2B_Update(&blake2bContext, data, bytesRead);
    }
    BLAKE2B_Final(hash, &blake2bContext);
    
    fclose(file);
}

// Function to compute hash using WHIRLPOOL
void computeWHIRLPOOL(const char *filename) {
    unsigned char hash[WHIRLPOOL_DIGEST_LENGTH];
    WHIRLPOOL_CTX whirlpoolContext;
    WHIRLPOOL_Init(&whirlpoolContext);
    
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Error opening file");
        exit(EXIT_FAILURE);
    }
    
    unsigned char data[1024];
    size_t bytesRead;
    while ((bytesRead = fread(data, 1, sizeof(data), file)) != 0) {
        WHIRLPOOL_Update(&whirlpoolContext, data, bytesRead);
    }
    WHIRLPOOL_Final(hash, &whirlpoolContext);
    
    fclose(file);
}

// Function to compute hash using XXHASH
void computeXXHASH(const char *filename) {
    XXH64_state_t* state = XXH64_createState();
    XXH64_reset(state, 0);
    
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Error opening file");
        exit(EXIT_FAILURE);
    }
    
    unsigned char data[1024];
    size_t bytesRead;
    while ((bytesRead = fread(data, 1, sizeof(data), file)) != 0) {
        XXH64_update(state, data, bytesRead);
    }
    XXH64_hash_t hash = XXH64_digest(state);
    
    fclose(file);
    XXH64_freeState(state);
}

int main() {
    const char *sizes[] = {"1MB", "10MB", "100MB", "1GB", "10GB"};
    const size_t fileSizes[] = {1 * MB, 10 * MB, 100 * MB, 1 * GB, 10 * GB};
    const char *hashAlgorithms[] = {"MD5", "SHA-1", "SHA-256", "SHA-512", "BLAKE2", "WHIRLPOOL", "XXHASH"};
    const int numAlgorithms = sizeof(hashAlgorithms) / sizeof(hashAlgorithms[0]);

    for (int i = 0; i < sizeof(fileSizes) / sizeof(fileSizes[0]); ++i) {
        printf("Generating %s dumb file...\n", sizes[i]);
        generateFile(sizes[i], fileSizes[i]);

        for (int j = 0; j < numAlgorithms; ++j) {
            printf("Computing hash using %s...\n", hashAlgorithms[j]);
            clock_t start = clock();
            if (strcmp(hashAlgorithms[j], "MD5") == 0) {
                computeMD5(sizes[i]);
            } else if (strcmp(hashAlgorithms[j], "SHA-1") == 0) {
                computeSHA1(sizes[i]);
            } else if (strcmp(hashAlgorithms[j], "SHA-256") == 0) {
                computeSHA256(sizes[i]);
            } else if (strcmp(hashAlgorithms[j], "SHA-512") == 0) {
                computeSHA512(sizes[i]);
            } else if (strcmp(hashAlgorithms[j], "SHA-3") == 0) {
                computeSHA3(sizes[i]);
            } else if (strcmp(hashAlgorithms[j], "BLAKE2") == 0) {
                computeBLAKE2(sizes[i]);
            } else if (strcmp(hashAlgorithms[j], "WHIRLPOOL") == 0) {
                computeWHIRLPOOL(sizes[i]);
            } else if (strcmp(hashAlgorithms[j], "XXHASH") == 0) {
                computeXXHASH(sizes[i]);
            }
            clock_t end = clock();
            double timeSpent = (double)(end - start) / CLOCKS_PER_SEC;
            printf("Time taken: %f seconds\n", timeSpent);
            printf("Average CPU demands: %f seconds\n", timeSpent / (double)fileSizes[i]);
        }

        // Clean up generated files
        remove(sizes[i]);
    }
