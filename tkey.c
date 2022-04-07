#include <openssl/rand.h>
#include <openssl/sha.h>
#include <stdint.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

#include "base32.h"

// Filenames
#define     K_FILENAME ".k"
#define    PK_FILENAME ".pk"
#define  SALT_FILENAME ".salt"
#define TINIT_FILENAME ".tinit"
#define    PI_FILENAME ".pi"
#define TPREV_FILENAME ".tprev"
#define PPREV_FILENAME ".pprev"

// File reading error messages
#define     K_FILE_READ_ERROR_MSG "Error when reading .k file.\n"
#define    PK_FILE_READ_ERROR_MSG "Error when reading .pk file.\n"
#define  SALT_FILE_READ_ERROR_MSG "Error when reading .salt file.\n"
#define TINIT_FILE_READ_ERROR_MSG "Error when reading .tinit file.\n"
#define    PI_FILE_READ_ERROR_MSG "Error when reading .pi file.\n"
#define TPREV_FILE_READ_ERROR_MSG "Error when reading .tprev file.\n"
#define PPREV_FILE_READ_ERROR_MSG "Error when reading .pprev file.\n"

// File writing error messages
#define     K_FILE_WRITE_ERROR_MSG "Error when writing .k file.\n"
#define    PK_FILE_WRITE_ERROR_MSG "Error when writing .pk file.\n"
#define  SALT_FILE_WRITE_ERROR_MSG "Error when writing .salt file.\n"
#define TINIT_FILE_WRITE_ERROR_MSG "Error when writing .tinit file.\n"
#define    PI_FILE_WRITE_ERROR_MSG "Error when writing .pi file.\n"
#define TPREV_FILE_WRITE_ERROR_MSG "Error when writing .tprev file.\n"
#define PPREV_FILE_WRITE_ERROR_MSG "Error when writing .pprev file.\n"

// User interface messages
#define    SETUP_COMPLETE "Setup complete.\n"
#define   PASS_GENERATION "New time-based password generated.\n"
#define PASS_VERIFICATION "Time-based password verification...\n"
#define  AUTH_FAILURE_MSG "Failed to authenticate.\n"
#define  AUTH_SUCCESS_MSG "Successfully authenticated!\n"

// Variables
#define           SALT_LENGTH 10      // 80 bits
#define           PASS_LENGTH 17      // 130 bits
#define BASE32_ENCODED_LENGTH 64
#define    TIME_SLOT_DURATION 30


int write_string_file(const char *filename,
                      uint8_t *value) {
    int r;
    FILE *file = fopen(filename, "w");
    if (file == NULL) {
        return 1;
    }
    r = fprintf(file, "%s", value);
    fclose(file);
    return 0;
}

int write_integer_file(const char *filename,
                       int value) {
    int r;
    FILE *file = fopen(filename, "w");
    if (file == NULL) {
        return 1;
    }
    r = fprintf(file, "%u", value);
    fclose(file);
    return 0;
}

void print_bits(uint8_t *s, int size) {
    int i, j;
    for(j = 0; j < size /* hardcoded bytes
    since sizeof and strlen seems to dismiss
    bytes of 8 zeroes */; j++) {
        for(i = 7; i >= 0; --i) {
            putchar((s[j] & 1 << i) ? '1' : '0');
        }
    }
    putchar('\n');
}

void print_hexs(uint8_t *hash, int size) {
    int j;
    for (j = 0; j < size; j++) {
        printf("%02x", hash[j]);
    }
    printf("\n");
}

int32_t gen_t() {
    time_t secs = time(NULL);
    return (int32_t) (secs / TIME_SLOT_DURATION);
}

int32_t get_tinit() {
    int32_t tinit;
    FILE *file = fopen(TINIT_FILENAME, "r");
    fscanf(file, "%" PRId32, &tinit);
    fclose(file);
    return tinit;
}

int32_t get_tprev() {
    int32_t tprev;
    FILE *file = fopen(TPREV_FILENAME, "r");
    fscanf(file, "%" PRId32, &tprev);
    fclose(file);
    return tprev;
}

int32_t get_k() {
    int32_t k;
    FILE *file = fopen(K_FILENAME, "r");
    fscanf(file, "%" PRId32, &k);
    fclose(file);
    return k;
}

void gen_pk(uint8_t *pk) {
    assert(RAND_bytes(pk, PASS_LENGTH) == 1);
    pk[PASS_LENGTH - 1] &= 0xC0; // 130 bits
}

void get_pk(uint8_t *pk) {
    uint8_t encoded[BASE32_ENCODED_LENGTH] = {0};
    FILE *file = fopen(PK_FILENAME, "r");
    fscanf(file, "%s", encoded);
    base32_decode(encoded, pk, BASE32_ENCODED_LENGTH);
    fclose(file);
}

void gen_salt(uint8_t *salt) {
    assert(RAND_bytes(salt, SALT_LENGTH) == 1);
}

void get_salt(uint8_t *salt) {
    uint8_t encoded[BASE32_ENCODED_LENGTH] = {0};
    FILE *file = fopen(SALT_FILENAME, "r");
    fscanf(file, "%s", encoded);
    base32_decode(encoded, salt, BASE32_ENCODED_LENGTH);
    fclose(file);
}

void gen_pi(int32_t tinit, uint8_t *salt,
           int32_t tmin,  int32_t tmax,
           uint8_t *pk,   uint8_t *pi,
           int32_t k) {

    int32_t t, i;

    uint8_t input[31] = {0}; // 242 bits
    uint8_t  hash[32] = {0}; // 256 bits

    if (tmin == tmax) {
        strncpy(pi, pk, PASS_LENGTH);
        return;
    }

    // Pasting secret key into the input
    strncpy(input + 14, pk, PASS_LENGTH);

    // Pasting salt (done only once, will never
    // change later) into the input
    strncpy(input + 4, salt, SALT_LENGTH);

    for (i = tmin; i < tmax; i++) {

        // Pasting time into the input
        t = tinit + k - i;
        //printf("t: %u\n", t);
        input[0] = (t & 0xFF000000) >> 24;
        input[1] = (t & 0x00FF0000) >> 16;
        input[2] = (t & 0x0000FF00) >> 8;
        input[3] = (t & 0x000000FF);

        // Hashing the input
        SHA256(input, 31, hash);
        // New chain value = 130 first bits of
        // hash (16 * 8 + 2)
        hash[PASS_LENGTH - 1] &= 0xC0;

        // Pasting 130 bits of new input into
        // old input
        strncpy(input + 14, hash, PASS_LENGTH);
    }

    // Retrieving the 130 first bits of the last
    // hash
    strncpy(pi, hash, PASS_LENGTH);
}

void get_pi(uint8_t *pi) {
    uint8_t encoded[BASE32_ENCODED_LENGTH] = {0};
    FILE *file = fopen(PI_FILENAME, "r");
    fscanf(file, "%s", encoded);
    base32_decode(encoded, pi, BASE32_ENCODED_LENGTH);
    fclose(file);
}

void get_pprev(uint8_t *pprev) {
    uint8_t encoded[BASE32_ENCODED_LENGTH] = {0};
    FILE *file = fopen(PPREV_FILENAME, "r");
    fscanf(file, "%s", encoded);
    base32_decode(encoded, pprev, BASE32_ENCODED_LENGTH);
    fclose(file);
}

void write_file_tinit(int32_t tinit) {
    if (write_integer_file(TINIT_FILENAME, tinit)) {
        printf(TINIT_FILE_WRITE_ERROR_MSG);
        exit(EXIT_FAILURE);
    }
}

void write_file_tprev(int32_t tprev) {
    if (write_integer_file(TPREV_FILENAME, tprev)) {
        printf(TPREV_FILE_WRITE_ERROR_MSG);
        exit(EXIT_FAILURE);
    }
}

void write_file_pk(uint8_t *pk) {
    uint8_t encoded[BASE32_ENCODED_LENGTH] = {0};
    base32_encode(pk, PASS_LENGTH, encoded, BASE32_ENCODED_LENGTH);
    if (write_string_file(PK_FILENAME, encoded)) {
        printf(PK_FILE_WRITE_ERROR_MSG);
        exit(EXIT_FAILURE);
    }
}

void write_file_salt(uint8_t *salt) {
    uint8_t encoded[BASE32_ENCODED_LENGTH] = {0};
    base32_encode(salt, SALT_LENGTH, encoded, BASE32_ENCODED_LENGTH);
    if (write_string_file(SALT_FILENAME, encoded)) {
        printf(SALT_FILE_WRITE_ERROR_MSG);
        exit(EXIT_FAILURE);
    }
}

void write_file_pprev(uint8_t *pprev) {
    uint8_t encoded[BASE32_ENCODED_LENGTH] = {0};
    base32_encode(pprev, PASS_LENGTH, encoded, BASE32_ENCODED_LENGTH);
    if (write_string_file(PPREV_FILENAME, encoded)) {
        printf(PPREV_FILE_WRITE_ERROR_MSG);
        exit(EXIT_FAILURE);
    }
}

void write_file_pi(uint8_t *pi) {
    uint8_t encoded[BASE32_ENCODED_LENGTH] = {0};
    base32_encode(pi, PASS_LENGTH, encoded, BASE32_ENCODED_LENGTH);
    if (write_string_file(PI_FILENAME, encoded)) {
        printf(PI_FILE_WRITE_ERROR_MSG);
        exit(EXIT_FAILURE);
    }
}

void setup() {

    int32_t tinit, k;
    uint8_t  salt[SALT_LENGTH] = {0};
    uint8_t    pk[PASS_LENGTH] = {0};
    uint8_t pinit[PASS_LENGTH] = {0};

    tinit = gen_t();
    k = get_k();
    gen_salt(salt);
    gen_pk(pk);
    gen_pi(tinit, salt, 1, k, pk, pinit, k);

    write_file_tinit(tinit);
    write_file_salt(salt);
    write_file_pk(pk);
    // Verifier's first [t|p]prev is [t|p]init
    write_file_tprev(tinit);
    write_file_pprev(pinit);

    printf(SETUP_COMPLETE);
}

void gen() {

    int32_t tinit, ti, i, k;
    uint8_t salt[SALT_LENGTH] = {0};
    uint8_t   pk[PASS_LENGTH] = {0};
    uint8_t   pi[PASS_LENGTH] = {0};

    tinit = get_tinit();
    k = get_k();
    ti = gen_t();
    i = ti - tinit;
    get_salt(salt);
    get_pk(pk);
    gen_pi(tinit, salt, 1, k - i, pk, pi, k);

    write_file_pi(pi);

    printf(PASS_GENERATION);
}

int check() {

    int32_t tinit, tprev, ti, i, k;
    uint8_t   salt[SALT_LENGTH] = {0};
    uint8_t  pprev[PASS_LENGTH] = {0};
    uint8_t pprevp[PASS_LENGTH] = {0};
    uint8_t     pi[PASS_LENGTH] = {0};

    printf(PASS_VERIFICATION);

    tinit = get_tinit();
    tprev = get_tprev();
    k = get_k();
    ti = gen_t();
    i = ti - tinit;
    get_salt(salt);
    get_pi(pi);
    get_pprev(pprev);
    gen_pi(tinit, salt, k - i, tinit + k - tprev, pi, pprevp, k);

    if (!strncmp(pprev, pprevp, PASS_LENGTH)) {
        write_file_tprev(ti);
        write_file_pprev(pi);
        printf(AUTH_SUCCESS_MSG);
    } else {
        printf(AUTH_FAILURE_MSG);
    }
}

int main(int argc, char* argv[]) {
    double max = 0;
    clock_t tot_start, tot_end;
    double sub_tot;
    double tot = 0;
    clock_t start, end;
   
    if (argc != 2) {
        printf("Usage: %s [mode]\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    
    if (!strncmp(argv[1], "0", 1))
        setup();
        
    else if (!strncmp(argv[1], "1", 1))
        gen();
        
    else if (!strncmp(argv[1], "2", 1))
        check();
        
    else if (!strncmp(argv[1], "time_setup", 1)){
        tot_start = clock();
        for (int j = 1; j <= 50; j++) { 
            start = clock();
            setup();
            end = clock();
            sub_tot = (double)(end - start)/CLOCKS_PER_SEC;
            if (sub_tot > max) {
                max = sub_tot;
            }
        }
        tot_end = clock();
        tot = (double)(tot_end - tot_start)/CLOCKS_PER_SEC;
        printf("Time for setup (in seconds): %lf\n",tot/50);
    }
    
    else if (!strncmp(argv[1], "time_gen", 1)){
        tot_start = clock();
        setup();
        for (int j = 1; j <= 50; j++) { 
            start = clock();
            gen();
            end = clock();
            sub_tot = (double)(end - start)/CLOCKS_PER_SEC;
            if (sub_tot > max) {
                max = sub_tot;
            }
        }
        tot_end = clock();
        tot = (double)(tot_end - tot_start)/CLOCKS_PER_SEC;
        printf("Time for password generation (in seconds): %lf\n",tot/50);
    }
    
    else if (!strncmp(argv[1], "time_check", 1)){
        tot_start = clock();
        setup();
        for (int j = 1; j <= 50; j++) { 
            gen();
            start = clock();
            check();
            end = clock();
            tot += (double)(end - start)/CLOCKS_PER_SEC;
        }
        tot_end = clock();
        printf("Time for password verification (in seconds): %lf\n",tot/50);
    }
    
    else
        printf("[mode] must be a value in {0, 1, 2}\n");
    
    return 0;
}

// TODO: manage all file reading/writing errors
