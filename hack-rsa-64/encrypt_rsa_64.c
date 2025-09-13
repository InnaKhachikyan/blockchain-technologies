#define LTM_DESC 1  

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <tomcrypt.h>
#include <tommath.h>

static char *mp_to_hexstr(const mp_int *x) {
    size_t need = mp_ubin_size(x);
    if (need == 0) need = 1;
    unsigned char *buf = (unsigned char*)malloc(need);
    if (!buf) return NULL;

    size_t written = 0;
    if (mp_to_ubin(x, buf, need, &written) != MP_OKAY) {
        free(buf);
        return NULL;
    }

    char *hexstr = (char*)malloc(written * 2 + 1);
    if (!hexstr) { free(buf); return NULL; }

    for (size_t i = 0; i < written; ++i)
        sprintf(hexstr + (i * 2), "%02x", buf[i]);
    hexstr[written * 2] = '\0';

    free(buf);
    return hexstr;
}

int main(void) {
    int err;
    ltc_mp = ltm_desc;

    if ((err = register_prng(&sprng_desc)) != CRYPT_OK) {
        fprintf(stderr, "register_prng: %s\n", error_to_string(err));
        return 1;
    }
    prng_state prng;
    if ((err = rng_make_prng(128, find_prng("sprng"), &prng, NULL)) != CRYPT_OK) {
        fprintf(stderr, "rng_make_prng: %s\n", error_to_string(err));
        return 1;
    }

    rsa_key key;
    const long e_pub = 65537;
    const int key_bytes = 8;  
    if ((err = rsa_make_key(&prng, find_prng("sprng"), key_bytes, e_pub, &key)) != CRYPT_OK) {
        fprintf(stderr, "rsa_make_key: %s\n", error_to_string(err));
        return 1;
    }

    const unsigned char msg[] = "KEY42";
    unsigned char ct[16];
    unsigned long ctlen = sizeof(ct);

    err = rsa_exptmod(msg, (unsigned long)strlen((const char*)msg),
                      ct, &ctlen, PK_PUBLIC, &key);
    if (err != CRYPT_OK) {
        fprintf(stderr, "rsa_exptmod(PK_PUBLIC): %s\n", error_to_string(err));
        rsa_free(&key);
        return 1;
    }

    char *n_hex = mp_to_hexstr((mp_int*)key.N);
    char *e_hex = mp_to_hexstr((mp_int*)key.e);

    if (!n_hex || !e_hex) {
        fprintf(stderr, "conversion error\n");
        rsa_free(&key);
        free(n_hex); free(e_hex);
        return 1;
    }

    FILE *f = fopen("rsa_output.txt", "w");
    if (!f) {
        perror("fopen");
        rsa_free(&key);
        free(n_hex); free(e_hex);
        return 1;
    }

    fprintf(f, "%s\n", n_hex);
    fprintf(f, "%s\n", e_hex);
    for (unsigned long i = 0; i < ctlen; ++i)
        fprintf(f, "%02x", ct[i]);
    fprintf(f, "\n");

    fclose(f);

    free(n_hex);
    free(e_hex);
    rsa_free(&key);

    return 0;
}

