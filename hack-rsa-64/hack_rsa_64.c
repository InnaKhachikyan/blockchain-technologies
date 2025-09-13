#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>

uint64_t hex_to_u64(const char *hex) {
    uint64_t val = 0;
    sscanf(hex, "%lx", &val);  
    return val;
}

unsigned char *hex_to_bytes(const char *hex, size_t *outlen) {
    size_t len = strlen(hex);
    *outlen = len / 2;
    unsigned char *buf = malloc(*outlen);
    if (!buf) return NULL;

    for (size_t i = 0; i < *outlen; i++) {
        sscanf(hex + 2*i, "%2hhx", &buf[i]);
    }
    return buf;
}

// the final result (the inverse) will be stored in bezout_coef var, 
// it might be negative, bring it to mod phi
void extended_euclid(uint64_t *phi, uint64_t *e, __int128 *bezout_coef, __int128 *other_coef) {
    if (*phi == 0) {
        *bezout_coef = 1;  
        *other_coef  = 0; 
        return;
    }

    uint64_t sub_phi = *e % *phi;
    uint64_t sub_e   = *phi;

    extended_euclid(&sub_phi, &sub_e, bezout_coef, other_coef);

    __int128 tmp = *bezout_coef - (__int128)(*e / *phi) * (*other_coef);

    *bezout_coef = *other_coef; 
    *other_coef  = tmp;        
}

static uint64_t powmod_u64(uint64_t base, uint64_t exp, uint64_t mod) {
    __uint128_t acc = 1, b = base % mod;
    while (exp) {
        if (exp & 1) acc = (acc * b) % mod;
        b = (b * b) % mod;
        exp >>= 1;
    }
    return (uint64_t)acc;
}

static uint64_t bytes_be_to_u64(const unsigned char *buf, size_t len) {
    uint64_t v = 0;
    for (size_t i = 0; i < len; i++) v = (v << 8) | buf[i];
    return v;
}

static void u64_to_bytes_be(uint64_t v, unsigned char *out, size_t len) {
    for (size_t i = 0; i < len; i++) {
        out[len - 1 - i] = (unsigned char)(v & 0xFF);
        v >>= 8;
    }
}

// works only for cipher under or equal to 8 bytes
uint8_t* decrypt_rsa(uint64_t n, uint64_t d, const unsigned char *cipher, size_t clen) {
    if (clen > 8) return NULL; 

    uint64_t c = bytes_be_to_u64(cipher, clen);
    uint64_t m = powmod_u64(c, d, n);

    uint8_t *plain = malloc(clen);
    if (!plain) return NULL;
    u64_to_bytes_be(m, plain, clen);
    return plain;
}

uint8_t* hack_rsa(uint64_t n, uint64_t e, unsigned char *ciphertext, size_t clen) {

    uint64_t p = 0, q = 0;                                       
    uint64_t root_n = (uint64_t)sqrt((double)n) + 1;
    if (n % 2 == 0) {
        p = 2;
        q = n / 2;
    } else {
        for (uint64_t i = 3; i <= root_n; i += 2) {            
            if (n % i == 0) {
                p = i;
                q = n / i;
                break;
            }
        }
    }
    if (p == 0 || q == 0) {                                  
        fprintf(stderr, "factorization failed\n");
        return NULL;
    }                                                      

    uint64_t phi_n = (p - 1) * (q - 1);
    __int128 d, other_coef;
    extended_euclid(&phi_n, &e, &d, &other_coef);

    //  signed modulus
    d %= (__int128)phi_n;     
    if (d < 0) {
        d += (__int128)phi_n; 
    }

    uint8_t *pt = decrypt_rsa(n, (uint64_t)d, ciphertext, clen); 
    if (!pt) {
        fprintf(stderr, "decrypt_rsa failed (clen>8?)\n");      
        return NULL;                                           
    }
    return pt;                                              
}

int main(void) {
    FILE *f = fopen("rsa_output.txt", "r");
    if (!f) { perror("fopen"); return 1; }

    char line[1024];

    if (!fgets(line, sizeof(line), f)) return 1;
    line[strcspn(line, "\r\n")] = '\0';
    uint64_t n = hex_to_u64(line);

    if (!fgets(line, sizeof(line), f)) return 1;
    line[strcspn(line, "\r\n")] = '\0';
    uint64_t e = hex_to_u64(line);

    if (!fgets(line, sizeof(line), f)) return 1;
    line[strcspn(line, "\r\n")] = '\0';
    size_t clen = 0;
    unsigned char *cipher = hex_to_bytes(line, &clen);

    fclose(f);

    printf("n = %llu\n", (unsigned long long)n);
    printf("e = %llu\n", (unsigned long long)e);
    printf("ciphertext (%zu bytes): ", clen);
    for (size_t i = 0; i < clen; i++) {
        printf("%02x", cipher[i]);
    }
    printf("\n");
    
    uint8_t *plaintext = hack_rsa(n, e, cipher, clen);
    if (!plaintext) {                                      
        free(cipher);
        return 1;
    }

    printf("plaintext (%zu bytes): ", clen);              
    for (size_t i = 0; i < clen; i++) printf("%02x", plaintext[i]); 
    printf("\n");                                               

    int msg_len = 5;
    printf("plaintext as chars: ");
	for (size_t i = clen - msg_len; i < clen; i++) {
    		printf("%c", plaintext[i]);
	}
	printf("\n");

    free(plaintext);                                          

    free(cipher);
    return 0;
}

