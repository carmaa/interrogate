/* ==========================================================================
 * twofish.c
 *
 * Twofish key schedule implementation for Interrogate
 *
 * Adapted for Interrogate use by Carsten Maartmann-Moe 
 * <maartman@stud.ntnu.no>, see full licencing details for original code 
 * below.
 * ==========================================================================
 */

/*
 ---------------------------------------------------------------------------
 Copyright (c) 1999, Dr Brian Gladman, Worcester, UK.   All rights reserved.
 
 LICENSE TERMS
 
 The free distribution and use of this software is allowed (with or without
 changes) provided that:
 
  1. source code distributions include the above copyright notice, this
     list of conditions and the following disclaimer;
 
  2. binary distributions include the above copyright notice, this list
     of conditions and the following disclaimer in their documentation;
 
  3. the name of the copyright holder is not used to endorse products
     built using this software without specific written permission.
 
 DISCLAIMER
 
 This software is provided 'as is' with no explicit or implied warranties
 in respect of its properties, including, but not limited to, correctness
 and/or fitness for purpose.
 ---------------------------------------------------------------------------
 
 My thanks to Doug Whiting and Niels Ferguson for comments that led
 to improvements in this implementation.
 
 Issue Date: 14th January 1999
*/

#include <stdio.h>
#include <stdlib.h>
#include "interrogate.h"

#define extract_byte(x,n)   ((unsigned char)((x) >> (8 * n)))

#define G_M 0x0169

unsigned char RS[4][8] = 
{
    { 0x01, 0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E, },
    { 0xA4, 0x56, 0x82, 0xF3, 0x1E, 0xC6, 0x68, 0xE5, },
    { 0x02, 0xA1, 0xFC, 0xC1, 0x47, 0xAE, 0x3D, 0x19, },
    { 0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E, 0x03, },
};

static unsigned char  tab_5b[4] =
    { 0, G_M >> 2, G_M >> 1, (G_M >> 1) ^ (G_M >> 2) };
static unsigned char  tab_ef[4] =
    { 0, (G_M >> 1) ^ (G_M >> 2), G_M >> 1, G_M >> 2 };

#define ffm_01(x)    (x)
#define ffm_5b(x)   ((x) ^ ((x) >> 2) ^ tab_5b[(x) & 3])
#define ffm_ef(x)   ((x) ^ ((x) >> 1) ^ ((x) >> 2) ^ tab_ef[(x) & 3])

static unsigned char ror4[16] = { 0, 8, 1, 9, 2, 10, 3, 11,
                                  4, 12, 5, 13, 6, 14, 7, 15 };
static unsigned char ashx[16] = { 0, 9, 2, 11, 4, 13, 6, 15,
                                  8, 1, 10, 3, 12, 5, 14, 7 };

static unsigned char qt0[2][16] =
    {   { 8, 1, 7, 13, 6, 15, 3, 2, 0, 11, 5, 9, 14, 12, 10, 4 },
        { 2, 8, 11, 13, 15, 7, 6, 14, 3, 1, 9, 4, 0, 10, 12, 5 }
    };

static unsigned char qt1[2][16] =
    {   { 14, 12, 11, 8, 1, 2, 3, 5, 15, 4, 10, 6, 7, 0, 9, 13 },
        { 1, 14, 2, 11, 4, 12, 3, 7, 6, 13, 10, 5, 15, 9, 0, 8 }
    };

static unsigned char qt2[2][16] =
    {   { 11, 10, 5, 14, 6, 13, 9, 0, 12, 8, 15, 3, 2, 4, 7, 1 },
        { 4, 12, 7, 5, 1, 6, 9, 10, 0, 14, 13, 8, 2, 11, 3, 15 }
    };

static unsigned char qt3[2][16] =
    {   { 13, 7, 15, 4, 1, 2, 6, 14, 9, 11, 3, 0, 8, 5, 12, 10 },
        { 11, 9, 5, 1, 12, 3, 13, 14, 6, 4, 7, 15, 2, 0, 8, 10 }
    };


static unsigned char qp(const unsigned int n, const unsigned char x) {
    unsigned char  a0, a1, a2, a3, a4, b0, b1, b2, b3, b4;

    a0 = x >> 4;
    b0 = x & 15;
    a1 = a0 ^ b0;
    b1 = ror4[b0] ^ ashx[a0];
    a2 = qt0[n][a1];
    b2 = qt1[n][b1];
    a3 = a2 ^ b2;
    b3 = ror4[b2] ^ ashx[a2];
    a4 = qt2[n][a3];
    b4 = qt3[n][b3];
    return (b4 << 4) | a4;
};

/* Q tables */

static unsigned int  qt_gen = 0;
static unsigned char  q_tab[2][256];

#define q(n,x)  q_tab[n][x]

static void gen_qtab(void) {
    unsigned int  i;

    for(i = 0; i < 256; ++i) {
        q(0,i) = qp(0, (unsigned char)i);
        q(1,i) = qp(1, (unsigned char)i);
    }
};

/* M tables */
static unsigned int  mt_gen = 0;
static unsigned int  m_tab[4][256];

static void gen_mtab(void) {
    unsigned int  i, f01, f5b, fef;

    for(i = 0; i < 256; ++i) {
        f01 = q(1,i);
        f5b = ffm_5b(f01);
        fef = ffm_ef(f01);
        m_tab[0][i] = f01 + (f5b << 8) + (fef << 16) + (fef << 24);
        m_tab[2][i] = f5b + (fef << 8) + (f01 << 16) + (fef << 24);

        f01 = q(0,i);
        f5b = ffm_5b(f01);
        fef = ffm_ef(f01);
        m_tab[1][i] = fef + (fef << 8) + (f5b << 16) + (f01 << 24);
        m_tab[3][i] = f5b + (f01 << 8) + (fef << 16) + (f5b << 24);
    }
};

#define mds(n,x)    m_tab[n][x]

static unsigned int h_fun(twofish_tc *instance, const unsigned int x,
                          const unsigned int key[]) {
    unsigned int  b0, b1, b2, b3;

    b0 = extract_byte(x, 0);
    b1 = extract_byte(x, 1);
    b2 = extract_byte(x, 2);
    b3 = extract_byte(x, 3);

    switch(instance->k_len) {
    case 4:
        b0 = q(1, (unsigned char) b0) ^ extract_byte(key[3],0);
        b1 = q(0, (unsigned char) b1) ^ extract_byte(key[3],1);
        b2 = q(0, (unsigned char) b2) ^ extract_byte(key[3],2);
        b3 = q(1, (unsigned char) b3) ^ extract_byte(key[3],3);
    case 3:
        b0 = q(1, (unsigned char) b0) ^ extract_byte(key[2],0);
        b1 = q(1, (unsigned char) b1) ^ extract_byte(key[2],1);
        b2 = q(0, (unsigned char) b2) ^ extract_byte(key[2],2);
        b3 = q(0, (unsigned char) b3) ^ extract_byte(key[2],3);
    case 2:
        b0 = q(0, (unsigned char) (q(0, (unsigned char) b0) ^
                                   extract_byte(key[1],0))) ^ 
                                   extract_byte(key[0],0);
        b1 = q(0, (unsigned char) (q(1, (unsigned char) b1) ^
                                   extract_byte(key[1],1))) ^ 
                                   extract_byte(key[0],1);
        b2 = q(1, (unsigned char) (q(0, (unsigned char) b2) ^
                                   extract_byte(key[1],2))) ^ 
                                   extract_byte(key[0],2);
        b3 = q(1, (unsigned char) (q(1, (unsigned char) b3) ^
                                   extract_byte(key[1],3))) ^ 
                                   extract_byte(key[0],3);
    }

    return  mds(0, b0) ^ mds(1, b1) ^ mds(2, b2) ^ mds(3, b3);
};

#define q20(x)  q(0,q(0,x) ^ extract_byte(key[1],0)) ^ extract_byte(key[0],0)
#define q21(x)  q(0,q(1,x) ^ extract_byte(key[1],1)) ^ extract_byte(key[0],1)
#define q22(x)  q(1,q(0,x) ^ extract_byte(key[1],2)) ^ extract_byte(key[0],2)
#define q23(x)  q(1,q(1,x) ^ extract_byte(key[1],3)) ^ extract_byte(key[0],3)

#define q30(x)  q(0,q(0,q(1, x) ^ extract_byte(key[2],0)) ^ extract_byte(key[1],0)) ^ extract_byte(key[0],0)
#define q31(x)  q(0,q(1,q(1, x) ^ extract_byte(key[2],1)) ^ extract_byte(key[1],1)) ^ extract_byte(key[0],1)
#define q32(x)  q(1,q(0,q(0, x) ^ extract_byte(key[2],2)) ^ extract_byte(key[1],2)) ^ extract_byte(key[0],2)
#define q33(x)  q(1,q(1,q(0, x) ^ extract_byte(key[2],3)) ^ extract_byte(key[1],3)) ^ extract_byte(key[0],3)

#define q40(x)  q(0,q(0,q(1, q(1, x) ^ extract_byte(key[3],0)) ^ extract_byte(key[2],0)) ^ extract_byte(key[1],0)) ^ extract_byte(key[0],0)
#define q41(x)  q(0,q(1,q(1, q(0, x) ^ extract_byte(key[3],1)) ^ extract_byte(key[2],1)) ^ extract_byte(key[1],1)) ^ extract_byte(key[0],1)
#define q42(x)  q(1,q(0,q(0, q(0, x) ^ extract_byte(key[3],2)) ^ extract_byte(key[2],2)) ^ extract_byte(key[1],2)) ^ extract_byte(key[0],2)
#define q43(x)  q(1,q(1,q(0, q(1, x) ^ extract_byte(key[3],3)) ^ extract_byte(key[2],3)) ^ extract_byte(key[1],3)) ^ extract_byte(key[0],3)

void gen_mk_tab(twofish_tc *instance, unsigned int key[]) {
    unsigned int  i;
    unsigned char  by;

    unsigned int *mk_tab = instance->mk_tab;

    switch(instance->k_len) {
    case 2:
        for(i = 0; i < 256; ++i) {
            by = (unsigned char)i;

            mk_tab[0 + 4*i] = mds(0, q20(by));
            mk_tab[1 + 4*i] = mds(1, q21(by));

            mk_tab[2 + 4*i] = mds(2, q22(by));
            mk_tab[3 + 4*i] = mds(3, q23(by));

        }
        break;

    case 3:
        for(i = 0; i < 256; ++i) {
            by = (unsigned char)i;

            mk_tab[0 + 4*i] = mds(0, q30(by));
            mk_tab[1 + 4*i] = mds(1, q31(by));

        }
        break;

    case 4:
        for(i = 0; i < 256; ++i) {
            by = (unsigned char)i;

            mk_tab[0 + 4*i] = mds(0, q40(by));
            mk_tab[1 + 4*i] = mds(1, q41(by));

            mk_tab[2 + 4*i] = mds(2, q42(by));
            mk_tab[3 + 4*i] = mds(3, q43(by));

        }
    }
};

#    define g0_fun(x) ( mk_tab[0 + 4*extract_byte(x,0)] ^ mk_tab[1 + 4*extract_byte(x,1)] \
                      ^ mk_tab[2 + 4*extract_byte(x,2)] ^ mk_tab[3 + 4*extract_byte(x,3)] )
#    define g1_fun(x) ( mk_tab[0 + 4*extract_byte(x,3)] ^ mk_tab[1 + 4*extract_byte(x,0)] \
                      ^ mk_tab[2 + 4*extract_byte(x,1)] ^ mk_tab[3 + 4*extract_byte(x,2)] )

#define G_MOD   0x0000014d

unsigned int mds_rem(unsigned int p0, unsigned int p1) {
    unsigned int  i, t, u;

    for(i = 0; i < 8; ++i) {
        t = p1 >> 24;   // get most significant coefficient
        p1 = (p1 << 8) | (p0 >> 24);
        p0 <<= 8;  // shift others up
        // multiply t by a (the primitive element - i.e. left shift)
        u = (t << 1);
        if(t & 0x80)            // subtract modular polynomial on overflow
            u ^= G_MOD;
        p1 ^= t ^ (u << 16);    // remove t * (a * x^2 + 1)
        u ^= (t >> 1);          // form u = a * t + t / a = t * (a + 1 / a);
        if(t & 0x01)            // add the modular polynomial on underflow
            u ^= G_MOD >> 1;
        p1 ^= (u << 24) | (u << 8); // remove t * (a + 1/a) * (x^3 + x)
    }

    return p1;
};

/* Initialise the key schedule from the user supplied key   */
void twofish_set_key(twofish_tc *instance, const unsigned int in_key[], const unsigned int key_len) {
    unsigned int  i, a, b, me_key[4], mo_key[4];
    unsigned int *l_key, *s_key;

    l_key = instance->l_key;
    s_key = instance->s_key;

    if(!qt_gen) {
        gen_qtab();
        qt_gen = 1;
    }

    if(!mt_gen) {
        gen_mtab();
        mt_gen = 1;
    }

    instance->k_len = key_len / 64;   /* 2, 3 or 4 */

    for(i = 0; i < instance->k_len; ++i) {
        a = in_key[i + i];
        me_key[i] = a;
        b = in_key[i + i + 1];
        mo_key[i] = b;
        s_key[instance->k_len - i - 1] = mds_rem(a, b);
    }

    for(i = 0; i < 40; i += 2) {
        a = 0x01010101 * i;
        b = a + 0x01010101;
        a = h_fun(instance, a, me_key);
        b = rotlFixed(h_fun(instance, b, mo_key), 8);
        l_key[i] = a + b;
        l_key[i + 1] = rotlFixed(a + 2 * b, 9);
    }
    gen_mk_tab(instance, s_key);

    return;
};

