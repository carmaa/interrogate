/* ==========================================================================
 * serpent.c
 *
 * Serpent key schedule implementation for Interrogate
 * 
 * Adapted from serpent.cpp -- written and placed in the public domain by Wei 
 * Dai. Interrogate version by Carsten Maartmann-Moe <carmaa@gmail.com>
 * ========================================================================== 
 */

#include <stdio.h>
#include <stdlib.h>
#include "interrogate.h"

/* -------
 * S-boxes
 * -------
 */
static void S0f (unsigned int *r0, unsigned int *r1, unsigned int *r2,
                 unsigned int *r3, unsigned int *r4) {
    *r3 ^= *r0;
    *r4 = *r1;
    *r1 &= *r3;
    *r4 ^= *r2;
    *r1 ^= *r0;
    *r0 |= *r3;
    *r0 ^= *r4;
    *r4 ^= *r3;
    *r3 ^= *r2;
    *r2 |= *r1;
    *r2 ^= *r4;
    *r4 = ~*r4;
    *r4 |= *r1;
    *r1 ^= *r3;
    *r1 ^= *r4;
    *r3 |= *r0;
    *r1 ^= *r3;
    *r4 ^= *r3;
}

static void S1f (unsigned int *r0, unsigned int *r1, unsigned int *r2,
                 unsigned int *r3, unsigned int *r4) {
    *r0 = ~*r0;
    *r2 = ~*r2;
    *r4 = *r0;
    *r0 &= *r1;
    *r2 ^= *r0;
    *r0 |= *r3;
    *r3 ^= *r2;
    *r1 ^= *r0;
    *r0 ^= *r4;
    *r4 |= *r1;
    *r1 ^= *r3;
    *r2 |= *r0;
    *r2 &= *r4;
    *r0 ^= *r1;
    *r1 &= *r2;
    *r1 ^= *r0;
    *r0 &= *r2;
    *r0 ^= *r4;
}

static void S2f (unsigned int *r0, unsigned int *r1, unsigned int *r2,
                 unsigned int *r3, unsigned int *r4) {
    *r4 = *r0;
    *r0 &= *r2;
    *r0 ^= *r3;
    *r2 ^= *r1;
    *r2 ^= *r0;
    *r3 |= *r4;
    *r3 ^= *r1;
    *r4 ^= *r2;
    *r1 = *r3;
    *r3 |= *r4;
    *r3 ^= *r0;
    *r0 &= *r1;
    *r4 ^= *r0;
    *r1 ^= *r3;
    *r1 ^= *r4;
    *r4 = ~*r4;
}

static void S3f (unsigned int *r0, unsigned int *r1, unsigned int *r2,
                 unsigned int *r3, unsigned int *r4) {
    *r4 = *r0;
    *r0 |= *r3;
    *r3 ^= *r1;
    *r1 &= *r4;
    *r4 ^= *r2;
    *r2 ^= *r3;
    *r3 &= *r0;
    *r4 |= *r1;
    *r3 ^= *r4;
    *r0 ^= *r1;
    *r4 &= *r0;
    *r1 ^= *r3;
    *r4 ^= *r2;
    *r1 |= *r0;
    *r1 ^= *r2;
    *r0 ^= *r3;
    *r2 = *r1;
    *r1 |= *r3;
    *r1 ^= *r0;
}

static void S4f (unsigned int *r0, unsigned int *r1, unsigned int *r2,
                 unsigned int *r3, unsigned int *r4) {
    *r1 ^= *r3;
    *r3 = ~*r3;
    *r2 ^= *r3;
    *r3 ^= *r0;
    *r4 = *r1;
    *r1 &= *r3;
    *r1 ^= *r2;
    *r4 ^= *r3;
    *r0 ^= *r4;
    *r2 &= *r4;
    *r2 ^= *r0;
    *r0 &= *r1;
    *r3 ^= *r0;
    *r4 |= *r1;
    *r4 ^= *r0;
    *r0 |= *r3;
    *r0 ^= *r2;
    *r2 &= *r3;
    *r0 = ~*r0;
    *r4 ^= *r2;
}

static void S5f (unsigned int *r0, unsigned int *r1, unsigned int *r2,
                 unsigned int *r3, unsigned int *r4) {
    *r0 ^= *r1;
    *r1 ^= *r3;
    *r3 = ~*r3;
    *r4 = *r1;
    *r1 &= *r0;
    *r2 ^= *r3;
    *r1 ^= *r2;
    *r2 |= *r4;
    *r4 ^= *r3;
    *r3 &= *r1;
    *r3 ^= *r0;
    *r4 ^= *r1;
    *r4 ^= *r2;
    *r2 ^= *r0;
    *r0 &= *r3;
    *r2 = ~*r2;
    *r0 ^= *r4;
    *r4 |= *r3;
    *r2 ^= *r4;
}

static void S6f (unsigned int *r0, unsigned int *r1, unsigned int *r2,
                 unsigned int *r3, unsigned int *r4) {
    *r2 = ~*r2;
    *r4 = *r3;
    *r3 &= *r0;
    *r0 ^= *r4;
    *r3 ^= *r2;
    *r2 |= *r4;
    *r1 ^= *r3;
    *r2 ^= *r0;
    *r0 |= *r1;
    *r2 ^= *r1;
    *r4 ^= *r0;
    *r0 |= *r3;
    *r0 ^= *r2;
    *r4 ^= *r3;
    *r4 ^= *r0;
    *r3 = ~*r3;
    *r2 &= *r4;
    *r2 ^= *r3;
}

static void S7f (unsigned int *r0, unsigned int *r1, unsigned int *r2,
                 unsigned int *r3, unsigned int *r4) {
    *r4 = *r2;
    *r2 &= *r1;
    *r2 ^= *r3;
    *r3 &= *r1;
    *r4 ^= *r2;
    *r2 ^= *r1;
    *r1 ^= *r0;
    *r0 |= *r4;
    *r0 ^= *r2;
    *r3 ^= *r1;
    *r2 ^= *r3;
    *r3 &= *r0;
    *r3 ^= *r4;
    *r4 ^= *r2;
    *r2 &= *r0;
    *r4 = ~*r4;
    *r2 ^= *r4;
    *r4 &= *r0;
    *r1 ^= *r3;
    *r4 ^= *r1;
}

static void LKf (unsigned int *k, unsigned int r, unsigned int *a,
                 unsigned int *b, unsigned int *c, unsigned int *d) {
    *a = k[r];
    *b = k[r + 1];
    *c = k[r + 2];
    *d = k[r + 3];
}

static void SKf (unsigned int *k, unsigned int r, unsigned int *a,
                 unsigned int *b, unsigned int *c, unsigned int *d) {
    k[r + 4] = *a;
    k[r + 5] = *b;
    k[r + 6] = *c;
    k[r + 7] = *d;
}

unsigned int LE32 (unsigned int x) {
    unsigned int n = (unsigned char) x;
    n <<= 8;
    n |= (unsigned char) (x >> 8);
    n <<= 8;
    n |= (unsigned char) (x >> 16);
    return (n << 8) | (unsigned char) (x >> 24);
}

/*
 * Sets the Serpent key schedule. Input: User supplied key, keysize in bytes,
 *  pointer to the key schedule storage.
 */
void serpent_set_key(const unsigned char userKey[], int keylen,
                     unsigned char *ks) {
    unsigned int a,b,c,d,e;
    unsigned int *k = (unsigned int *)ks;
    unsigned int t;
    int i;

    for (i = 0; i < keylen / (int)sizeof(int); i++)
        k[i] = ((unsigned int*)userKey)[i];

    if (keylen < 32)
        k[keylen/4] |= (unsigned int)1 << ((keylen%4)*8);

    k += 8;
    t = k[-1];
    for (i = 0; i < 132; ++i)
        k[i] = t = rotlFixed(k[i-8] ^ k[i-5] ^ k[i-3] ^ t ^ 0x9e3779b9 ^ i,
                             11);
    k -= 20;

    for (i=0; i<4; i++) {
        LKf (k, 20, &a, &e, &b, &d);
        S3f (&a, &e, &b, &d, &c);
        SKf (k, 16, &e, &b, &d, &c);

        LKf (k, 24, &c, &b, &a, &e);
        S2f (&c, &b, &a, &e, &d);
        SKf (k, 20, &a, &e, &b, &d);

        LKf (k, 28, &b, &e, &c, &a);
        S1f (&b, &e, &c, &a, &d);
        SKf (k, 24, &c, &b, &a, &e);

        LKf (k, 32, &a, &b, &c, &d);
        S0f (&a, &b, &c, &d, &e);
        SKf (k, 28, &b, &e, &c, &a);

        k += 8*4;

        LKf (k,  4, &a, &c, &d, &b);
        S7f (&a, &c, &d, &b, &e);
        SKf (k,  0, &d, &e, &b, &a);

        LKf (k,  8, &a, &c, &b, &e);
        S6f (&a, &c, &b, &e, &d);
        SKf (k,  4, &a, &c, &d, &b);

        LKf (k, 12, &b, &a, &e, &c);
        S5f (&b, &a, &e, &c, &d);
        SKf (k,  8, &a, &c, &b, &e);

        LKf (k, 16, &e, &b, &d, &c);
        S4f (&e, &b, &d, &c, &a);
        SKf (k, 12, &b, &a, &e, &c);
    }
    LKf (k, 20, &a, &e, &b, &d);
    S3f (&a, &e, &b, &d, &c);
    SKf (k, 16, &e, &b, &d, &c);
}

