/* ==========================================================================
 * util.c
 *
 * Utility toolbox for Interrogate
 *
 * Author: Carsten Maartmann-Moe <carmaa@gmail.com>
 * ==========================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "interrogate.h"

/*
 * Open file, return pointer
 */
FILE *open_file(interrogate_context *ctx, char *filename, char *mode) {
    struct stat st; 		/* Stat struct for input file */
    FILE *fp; 				/* Pointer to input file */
    if (stat(filename, &st) == -1) {
        perror("stat()");
        fprintf(stderr, "Failed to stat %s.\n", filename);
        exit(-1);
    } else {
        ctx->filelen = st.st_size;
    }

    fp = fopen(filename, mode);
    if (fp == NULL) {
        perror("fopen()");
        fprintf(stderr, "Failed to open %s.\n", filename);
        exit(-1);
    }
    return fp;
}

/*
 * Reads entire file into memory and returns buffer
 */
unsigned char *read_file(interrogate_context *ctx, FILE *fp) {
    unsigned char *buffer; /* Buffer (entire file) */

    /* Get the length of the file and rewind */
    fseek(fp, 0L, SEEK_END);
    ctx->filelen = ftell(fp);
    rewind(fp);

    /* Try to allocate enough memory for entire file. Should work for
     * large files if the system uses virtual memory. calloc() 
     * initializes all bytes to 0, so we don't have to worry about 
     * setting the NULL-terminator. */
    buffer = calloc(ctx->filelen + 1, sizeof(unsigned char));
    if (buffer == NULL) {
        fprintf(stderr, "Not enough memory to read entire file.\n");
        exit(1);
    }

    /* Read file into buffer */
    printf("Attempting to load entire file into memory, please stand "
           "by...\n");
    size_t res = fread(buffer, 1, ctx->filelen, fp);
    if (res != ctx->filelen) {
        fprintf(stderr, "Reading error.\n");
        exit(3);
    }

    return buffer;
}

/*
 * Prints info about entropy blobs 
 */
void printblobinfo(int start, int end, int bytes, float wins, float ent) {
    printf(" %.8x - %.8x | %8i | %7.2f | %f \n",
           start, end, bytes, wins, ent);
}

/*
 * Prints raw data in hexadecimal form to stdout. Bytes are separated wiht
 * spaces, and linefeeds are inserted after 'column' bytes
 */
void print_hex_array(unsigned char *buffer, int length, int columns) {
    int i;
    for (i = 0; i < length; i++) {
        if ((i % columns) == 0)
            printf("\n");
        printf("%02x ", buffer[i]);
    }
    printf("\n\n");
}

/*
 * Prints raw data in hexadecimal, 32-bit word, little-endian form to stdout.
 * Words are separated with spaces, and linefeeds are inserted after 
 * 'columns' words
 */
void print_hex_words(unsigned int *buffer, int length, int columns) {
    int i;
    for (i = 0; i < length; i++) {
        if ((i % columns) == 0)
            printf("\n");
        printf("%08x ", buffer[i]);
    }
    printf("\n\n");
}

/*
 * Windows getopt() :-/
 */
#ifdef _WIN32
static int optind = 1;

static int getopt(int argc, char *argv[], char *opts) {
    static char *opp = NULL;
    int o;

    while (opp == NULL) {
        if ((optind >= argc) || (*argv[optind] != '-')) {
            return -1;
        }
        opp = argv[optind] + 1;
        optind++;
        if (*opp == 0) {
            opp = NULL;
        }
    }
    o = *opp++;
    if (*opp == 0) {
        opp = NULL;
    }
    return strchr(opts, o) == NULL ? '?' : o;
}
#endif

void print_to_file(FILE *fp, float value) {
    char str[30];
    snprintf(str, 30, "%.4g", value);
    strncat(str, "\n", 1);
    fputs(str, fp);
}

unsigned getbits(unsigned x, int p, int n) {
    return (x >> (p + 1 - n)) & ~(~0 << n);
}

/*
 * Truncates of the nPrecision last digits of a float 
 */
double format(double Value, int nPrecision) {
    char *buffer = malloc(128*sizeof(char));
    snprintf(buffer,127,"%0.*f",nPrecision,Value);
    double d = atof(buffer);
    free(buffer);
    return d;
}

/*
 * Checks if the runs lies within a relaxed set of heuristic values.
 */
int is_mk_tab(int *run) {
    return (run[0] < 520 &&
            run[0] > 485 &&
            run[1] == 0 &&
            run[2] <= 12 &&
            run[2] >= 1 &&
            run[3] == 0 &&
            run[4] == 0 &&
            run[5] <= 1 &&
            run[5] >= 0);
}

/*
 * Heuristic check for Twofish sub- and whitening keys
 */
int is_l_key(interrogate_context *ctx, unsigned int *l_key) {
    float entropy = ent(ctx, (unsigned char *)l_key, 160);
    return (entropy < 7.2 && entropy > 6.3);
}

/*
 * Heuristic check for Twofish S-box keys
 */
int is_s_key(interrogate_context *ctx, unsigned int *s_key) {
    float entropy = format(ent(ctx, (unsigned char *)s_key, 16), 4);
    return (entropy == 4.0000 ||
            entropy == 3.8750 ||
            entropy == 3.7500 ||
            entropy == 3.7028 ||
            entropy == 3.6250 ||
            entropy == 3.5778 ||
            entropy == 3.5000 ||
            entropy == 3.4528 ||
            entropy == 3.4056 ||
            entropy == 3.3750 ||
            entropy == 3.3278 ||
            entropy == 3.2806 ||
            entropy == 3.2744 ||
            entropy == 3.2500 ||
            entropy == 3.2028 ||
            entropy == 3.1556 ||
            entropy == 3.1494 ||
            entropy == 3.1250 ||
            entropy == 3.0778 ||
            entropy == 3.0306 ||
            entropy == 3.0244 ||
            ((entropy <= 3.0000) &&
             (entropy >= 2.0000)));
}

/*
 * Validates a Twofish key schedule by structural checkups. Prints info.
 */
void validate_tf_ks(interrogate_context *ctx, unsigned char *buffer,
                    int offset) {
    float entropy;
    /* Try each of the different structs, and return the first match */

    /* Truecrypt */
    int tc_offs = offset - (44 * sizeof(unsigned int));
    if (tc_offs >= 0) {
        twofish_tc *tc = (twofish_tc *) (buffer + tc_offs);
        entropy = ent(ctx, (unsigned char *)tc->mk_tab,
                      sizeof(tc->mk_tab));
        if (entropy == 8 && tc->k_len == 4) {
            if (is_l_key(ctx, tc->l_key)) {
                if(is_s_key(ctx, tc->s_key)) {
                    printf("Truecrypt Twofish key found at %08x. "
                           "Expanded key:\n", tc_offs);
                    printf("Key words:");
                    print_hex_words((unsigned int *)tc->l_key,
                                    (sizeof(tc->l_key)) / 4, 4);
                    printf("S-box keys:");
                    print_hex_words((unsigned int *)tc->s_key,
                                    sizeof(tc->s_key) / 4, 4);
                    printf("S-box array:");
                    print_hex_words((unsigned int *)tc->mk_tab,
                                    sizeof(tc->mk_tab) / 4, 4);
                    printf("Key length:");
                    print_hex_words(&tc->k_len,
                                    sizeof(tc->k_len) / 4, 4);
                    ctx->count++;
                }
            }
        }
    }

    /* Optimized */
    int opt_offs = offset - (41 * sizeof(unsigned int));
    if (opt_offs >= 0) {
        twofish_opt *tc4 = (twofish_opt *) (buffer + opt_offs);
        entropy = ent(ctx, (unsigned char *)tc4->QF,
                      sizeof(tc4->QF));
        if (entropy == 8 && (tc4->k_len == 0 || tc4->k_len == 1) ) {
            if (is_l_key(ctx, tc4->K)) {
                printf("Twofish key found at %08x. Expanded key:\n\n",
                       opt_offs);
                printf("Key words:");
                print_hex_words((unsigned int *)tc4->K,
                                (sizeof(tc4->K)) / 4, 4);
                printf("S-box array:");
                print_hex_words((unsigned int *)tc4->QF,
                                (sizeof(tc4->QF)) / 4, 4);
                ctx->count++;
            }
        }
    }

    /* GPG/Linux and SSH */
    twofish_gpg *tc2 = (twofish_gpg *) (buffer + offset);
    entropy = ent(ctx, (unsigned char *)tc2->s,
                  sizeof(tc2->s));
    if (entropy == 8) {
        if (is_l_key(ctx, tc2->w)) {
            printf("GPG or SSH Twofish key found at %08x. Expanded key:\n",
                   offset);
            printf("Key words:");
            print_hex_words((unsigned int *)tc2->w,
                            (sizeof(tc2->w) + sizeof(tc2->k)) / 4, 4);
            printf("S-box array:");
            print_hex_words((unsigned int *)tc2->s,
                            (sizeof(tc2->s)) / 4, 4);
            ctx->count++;
        }
    }

    /* Nettle */
    int nettle_offs = offset - (40 * sizeof(unsigned int));
    if (nettle_offs >= 0) {
        twofish_nettle *tc3 = (twofish_nettle *) (buffer + nettle_offs);
        entropy = ent(ctx, (unsigned char *)tc3->s,
                      sizeof(tc3->s));
        if (entropy == 8) {
            if (is_l_key(ctx, tc3->k)) {
                printf("Nettle Twofish key found at %08x. Expanded key:\n\n",
                       nettle_offs);
                printf("Key words:");
                print_hex_words((unsigned int *)tc3->k,
                                (sizeof(tc3->k)) / 4, 4);
                printf("S-box array:");
                print_hex_words((unsigned int *)tc3->s,
                                (sizeof(tc3->s)) / 4, 4);
                ctx->count++;
            }
        }
    }


}
