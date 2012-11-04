/* ==========================================================================
 * interrogate.h
 *
 * Main header file for Interrogate: Structural and entropy-based search for 
 * crypto keys in binary files or memory dumps. 
 * 
 * http://interrogate.sourceforge.net
 *
 * Copyright (C) 2008 Carsten Maartmann-Moe <carmaa@gmail.com>
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * ==========================================================================
 */

#define NOFSYMBOLS      256 /* Number of symbols in alphabet (ASCII=256) */
#define WINDOWSIZE      256 /* Windowsize in BYTES */
#define KEYSIZE         256 /* Default keysize in BITS */
#define THRESHOLD       7.0 /* Default entropy threshold */
#define BCMOD           20  /* Modifier for byte count threshold */
#define TRUE            1
#define FALSE           0

#define NO_KEYTYPE      -1  /* Keytype definitions below */
#define AES             0
#define RSA             1
#define SERPENT         2
#define TWOFISH         3
#define TWOFISH_TC      4
#define RSAWIN          5
#define NOF_KEYTYPES    6

#define LEFT 0
#define RIGHT 1

#define rotlFixed(x,n)   (((x) << (n)) | ((x) >> (32 - (n))))
#define rotrFixed(x,n)   (((x) >> (n)) | ((x) << (32 - (n))))

#define NOF_TF_IMP		4;  /* Number of Twofish implementations */
#define TF_SBOX_SIZE	4096;
#define TF_RUNS			6	/* Runs to measure */

/* ----------------------------
 * Twofish key structures below
 * ----------------------------
 */

/* Twofish key structure, taken from TrueCrypt implementation */
typedef struct {
    unsigned int l_key[40];
    unsigned int s_key[4];
    unsigned int mk_tab[4 * 256];
    unsigned int k_len;
}
twofish_tc;

/* Twofish key sructure from Linux and GPG implementations
 * Isomorphic with SSH impelentation below as far as we are concered. */
typedef struct {
    unsigned int s[4][256], w[8], k[32];
}
twofish_gpg;

/* SSH twofish key schedule */
typedef struct {
    unsigned int s[4][256];               /* Key-dependant S-Boxes */
    unsigned int k[40];                   /* Expanded key words    */
    int for_encryption;                   /* encrypt / decrypt     */
}
twofish_ssh;

/* Twofish key structure taken from Nettle */
typedef struct {
    unsigned int k[40];
    unsigned int s[4][256];
}
twofish_nettle;

/* Twofish optimized implementation */
typedef struct {
    unsigned int K[40];
    unsigned int k_len;
    unsigned int QF[4][256];
}
twofish_opt;

/* Page Table Entry struct (PTE). Note that Windows uses the
 * same structure for Page Directory Entries (PDEs).
 */
typedef struct {
unsigned int valid :
    1;
unsigned int write :
    1;
unsigned int owner :
    1;
unsigned int write_through :
    1;
unsigned int cache_disabled :
    1;
unsigned int accessed :
    1;
unsigned int dirty :
    1;
unsigned int large_page :
    1;
unsigned int global :
    1;
unsigned int copy_on_write :
    1;
unsigned int transition :
    1;
unsigned int prototype :
    1;
unsigned int pfn :
    20;
}
pte;

/* Virtual address for 32-bit x86 Windows systems */
typedef struct {
unsigned int byte_offset :
    12;
unsigned int pt_index :
    10;
unsigned int pd_index :
    10;
}
virtual_address;

/* DWORD and WORD type definitions */
typedef unsigned long DWORD;
typedef unsigned short WORD;

/* Interrogate context */
typedef struct {
    int     keytype,        /* Keytype to be searched for */
    keysize,                /* The key size that are to be searched for */
    wsize,                  /* The search window size */
    nofs,                   /* The number of symbols in our alphabet */
    bitmode,                /* Bitmode boolean */
    verbose,                /* Verbose mode */
    naivemode,              /* Calculate true entropy */
    quickmode,              /* Non-overlapping entropy windows */
    interval,               /* Only search in interval (boolean) */
    from,                   /* Starting point */
    to,                     /* End point */
    cr3,                    /* CR3 offset in case recunstruction of mem */
    filelen,                /* Input file length in bytes */
    bytethreshold;          /* Threshold for bytecount */
    FILE    *output_fp;     /* Pointer to output file for statistics */
    float   threshold;      /* Entropy threshold */
    long    count;          /* Number of keys found */
}
interrogate_context;

/* -------------------
 * Function prototypes
 * -------------------
 */

/* interrogate.c: Main Program */
void init(float *ek);
void initialize();
void keysearch(interrogate_context *ctx, unsigned char *buffer);
void search(interrogate_context *ctx, unsigned char *buffer);
void quicksearch(interrogate_context *ctx, unsigned char *buffer);
void rsa_search(interrogate_context *ctx, unsigned char *buffer);
void rsa_win_search(interrogate_context *ctx, unsigned char *buffer);
void aes_search(interrogate_context *ctx, unsigned char *buffer);
void serpent_search(interrogate_context *ctx, unsigned char *buffer);
void twofish_search(interrogate_context *ctx, unsigned char *buffer);
void twofish_search_old(interrogate_context *ctx, unsigned char *buffer);

/* stat.c: Statistics */
double approxlog2(double x);
float ent(interrogate_context *ctx, unsigned char *buffer, int length);
float *ent_opt(unsigned char *buffer);
int countbytes(interrogate_context *ctx, unsigned char *buffer);
void runs(interrogate_context *ctx, unsigned char *buffer, int *runs_count,
          int run_length, int *firstrun, int *lastrun);
void runs_opt(interrogate_context *ctx, unsigned char *buffer,
              int *runs_count, int run_length, int *firstrun, int *lastrun);

/* rsa.c: RSA functions */
int parse_der(unsigned char *buffer, int offset);
void output_der(unsigned char *buffer, int offset, size_t size, long *count);

/* aes.c: AES functions */
void rotate(unsigned char *in);
unsigned char rcon(unsigned char in);
unsigned char gmul(unsigned char a, unsigned char b);
unsigned char gmul_inverse(unsigned char in);
unsigned char sbox(unsigned char in);
void schedule_core(unsigned char *in, unsigned char i);
void expand_key(unsigned char *in);
void expand_key_192(unsigned char *in);
void expand_key_256(unsigned char *in);

/* serpent.c: Serpent functions */
void serpent_set_key(const unsigned char userKey[], int keylen,
                     unsigned char *ks);

/* twofish.c TwoFish functions */
void twofish_set_key(twofish_tc *instance, const unsigned int in_key[],
                     const unsigned int key_len);
unsigned int mds_rem(unsigned int p0, unsigned int p1);
void gen_mk_tab(twofish_tc *instance, unsigned int key[]);

/* nppool.c Nonpaged Pool functions */
void reconstruct(interrogate_context *ctx, unsigned char *buffer);
void print_pte(virtual_address *addr, pte *pd, pte *pde, pte *pt, pte *pte,
               unsigned char *page);

/* util.c: Utility functions */
unsigned char *read_file(interrogate_context *ctx, FILE *fp);
FILE *open_file(interrogate_context *ctx, char *filename, char *mode);
int checkbyte(unsigned char index, int *array);
void printblobinfo(int start, int end, int bytes, float wins, float entropy);
void print_hex_array(unsigned char *buffer, int length, int columns);
void print_hex_words(unsigned int *buffer, int length, int columns);
int validkeytype(char *keytype, int length);
int min(int a, int b);
void print_to_file(FILE *fp, float value);
unsigned getbits(unsigned x, int p, int n);
unsigned int byteshift(unsigned int x, int direction, int n);
int is_mk_tab(int *run);
void validate_tf_ks(interrogate_context *ctx, unsigned char *buffer,
                    int offset);
double format(double Value, int nPrecision);

