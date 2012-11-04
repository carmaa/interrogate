/* ==========================================================================
 * stat.c
 *
 * Statistcal functions used in Interrogate
 *
 * Author: Carsten Maartmann-Moe <carmaa@gmail.com>
 * ==========================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>

#include "interrogate.h"

#define LOG2OF10 3.32192809488736234787

int r[6] = {0, 0, 0, 0, 0, 0};

/*
 * Calculate log2 
 */
double approxlog2(double x) {
    return LOG2OF10 * log10(x);
}

/*
 * Calculates entropy of char array, with length window size and 'nofs' 
 * symbols.
 */
float ent(interrogate_context *ctx, unsigned char *buffer, int length) {
    int i, count = 0;   /* Counters */
    float entropy = 0.0;    /* The entropy */
    unsigned char c;    /* Char read from file buffer */
    int *ccount;        /* Bins for counting chars */
    float *p;       /* Bins for char probabilities */

    /* Reserve space. ccount is zeroed out, p is not (we're iterating through
     * p later anyways).*/
    ccount = (int *) calloc(ctx->nofs, sizeof(int));
    p = (float *) malloc(ctx->nofs * sizeof(float));

    /* Count occurrences of each char and the total count within window */
    while (count < length) {
        c = (unsigned char) *buffer++;
        ccount[c]++;
        count++;
    }

    /* Calculate probabilitiy of each char, and update entropy */
    for (i = 0; i < ctx->nofs; i++) {
        p[i] = ((float) ccount[i]) / length;
        if (p[i] > 0.0)
            entropy -= (float) p[i] * approxlog2(p[i]);
    }
    free(ccount);
    free(p);
    return entropy;
}

/*
 * Returns the minimum value of two ints
 */
int min(int a, int b) {
    return (a < b)? a : b;
}

/*
 * Checks if a byte in an array is set. The unsigned char is simply
 * the index in the array that has to be checked.
 */
int checkbyte(unsigned char index, int *array) {
    return array[index];
}

/*
 * Counts number of unique bytes within a non-overlapping window.
 */
int countbytes(interrogate_context *ctx, unsigned char *buffer) {
    int count = 0;      /* Window counter */
    int bytecount = 0;  /* The unique byte counter */
    int *ccount;        /* Bins for already discovered bytes */
    unsigned char c;    /* Char read from file buffer */

    ccount = (int *) calloc(ctx->nofs, sizeof(int));

    while ( count < ctx->wsize ) {
        c = (unsigned char) *buffer++;
        if (ccount[c] == 0) {
            ccount[c]++;
            bytecount++;
        }
        count++;
    }
    free(ccount);
    return bytecount;
}

/*
 * Count byte runs. A one-byte run is defined as two sequential bytes of 
 * equal value. Thus, a six-byte run of 0x41 is actually seven sequential 
 * 0x41s. All runs longer than 'run_length' are counted in the last bin, e.g.
 * as a 'run_length'-byte run. A call to this method is required to 
 * initialize the optimized runs method 'runs_opt'.
 */
void runs(interrogate_context *ctx, unsigned char *buffer, int *runs_count,
          int run_length, int *firstrun, int *lastrun) {
    int i;
    int overflow = 0;
    unsigned char last = 0;
    int current_run = 0;
    memset(runs_count, 0, run_length * sizeof(int));
    for (i = 0; i < ctx->wsize; i++) {
        unsigned char c = buffer[i];
        /* Don't count the first char as a run */
        if (i != 0) {
            if (c == last) {
                if (current_run < run_length) {
                    /* Only decrement counter if such a bin exists */
                    if (current_run != 0)
                        runs_count[current_run - 1]--;
                    runs_count[current_run]++;
                    current_run++;
                } else {
                    overflow++;
                }
            } else {
                /* Check if the run went on from the start; if so save */
                if (i == current_run + overflow + 1) {
                    *firstrun = current_run;
                }
                /* Reset runs counters */
                current_run = overflow = 0;
            }
        }
        last = c;
    }
    /* Save if the last char was a part of a run */
    *lastrun = current_run;
}

/*
 * Optimized 'runs' method. See runs(). Needs to be initialized by a call
 * to runs() before excecution; to count runs in the initial window, and
 * set lastrun and firstrun counters. The algorithm basically keeps track of
 * the runs in the ends of the buffer, and increments and decrements run
 * counts as needed. It is intended to work on a unsigned char buffer, and be
 * fed sub-buffers of this buffer in a sequential fashion. For example, a
 * call procedure like this will work:
 * 
 * int *runs_count = {0, 0, 0, 0, 0, 0}; // Initalize array for storage
 * lastrun = firstrun = 0; // Initialize counters
 * runs(...); // Initialize by calling 'runs()' function
 * for (i = 0; i < buffersize; i++) {
 *     runs_opt(context, &buffer[i], runs_count, ...);
 * }
 * 
 * This method has a significant performance gain compared to calling runs
 * sequentially, typically linear vs. exponential time complexity. For some
 * reason, this method is known to not work with gcc optimization e.g., no
 * -Ox options.
 */
void runs_opt(interrogate_context *ctx, unsigned char *buffer,
              int *runs_count, int run_length, int *firstrun, int *lastrun) {
    unsigned char *buf_ptr = buffer;
    int new_firstrun = 0;
    /* Count the new first run */
    while((*buf_ptr == *++buf_ptr) && new_firstrun < run_length) {
        new_firstrun++;
    }
    if (ctx->wsize < 2 * run_length) {
        fprintf(stderr, "A window size of at least two times the run "
                "length is required for this function to work.\n");
        exit(-1);
    }
    /* Since C indexes runs from 0 we need to subtract one from every
     * count to form indices in the runs_count table. If the new firs run 
           * is its maximum, it implies that the counts should not be 
           * decremented
     */
    if (*firstrun > 0 && !(new_firstrun == 6)) {
        /* Decrement bin count for the byte that "fell out" */
        runs_count[*firstrun - 1]--;
        /* Subract the byte that "fell out" of the buffer */
        (*firstrun)--;
        /* If there exists a bin for a smaller run, increment it */
        if (*firstrun != 0)
            runs_count[*firstrun - 1]++;
    } else {
        /* Count an eventual new run */
        *firstrun = new_firstrun;
    }
    /* Check if the last two chars in the buffer match */
    if (buffer[ctx->wsize - 2] == buffer[ctx->wsize - 1]) {
        /* Decrement the count for the previous run */
        if (*lastrun > 0)
            runs_count[*lastrun - 1]--;
        /* Increment lastrun if its less than max run length */
        if (*lastrun < run_length)
            (*lastrun)++;
        /* Increment bin for current count */
        runs_count[*lastrun - 1]++;
    } else {
        /* Reset lastrun if the two last chars doesn't match */
        *lastrun = 0;
    }
}
