/* ==========================================================================
 * rsa.c
 *
 * RSA-specific methods for Interrogate. Parses DER-encoded blobs and ouputs
 * to file in the format privkey-00x.der
 *
 * Author: Carsten Maartmann-Moe <carmaa@gmail.com>
 * ==========================================================================
 */

#include <stdio.h>
#include <stdlib.h>

#include "interrogate.h"

/* Perform basic structural check on possible DER-encoded private key.
 * Returns 0 if invalid, and the length of the DER blob if it is valid. Also 
 * prints some info about the key. 
 */
int parse_der(unsigned char *buffer, int offset) {
    if (buffer[offset + 4] == 0x02 &&
            buffer[offset + 5] == 0x01 &&
            buffer[offset + 6] == 0x00 &&
            buffer[offset + 7] == 0x02) {
        int length = (buffer[offset+2] << 8) |
                     (unsigned char) buffer[offset+3];
        int end = 4 + length;
        int pub_exp_field_length = 0;
        int modlength, asn1length = (unsigned char) buffer[offset + 8];
        if ((asn1length & 0x80) == 0) {
            modlength = asn1length;
            pub_exp_field_length = 1;
        } else {
            int numbytes = asn1length & 0x7F;
            if (numbytes <= 8) {
                int i;
                pub_exp_field_length = 1 + numbytes;
                modlength = (unsigned char) buffer[offset + 9];
                for (i = 1; i < numbytes; i++) {
                    modlength = (modlength << 8) |
                                    (unsigned char) buffer[offset + 9 + i];
                }
            } else {
                printf("Found modulus length > 64 bits, this is not "
                       "supported.");
                return 0;
            }
        }
        int pub_exp_offset = offset + 8 + pub_exp_field_length + modlength;
        int pub_exp = 0;
        if (buffer[pub_exp_offset] == 0x02) {
            if (buffer[pub_exp_offset + 1] == 0x01 &&
                    buffer[pub_exp_offset + 2] == 0x01) {
                pub_exp = 1;
            } else if (buffer[pub_exp_offset + 1] == 0x03 &&
                       buffer[pub_exp_offset + 2] == 0x01 &&
                       buffer[pub_exp_offset + 3] == 0x00 &&
                       buffer[pub_exp_offset + 4] == 0x01) {
                pub_exp = 65537;
            } else {
                printf("Could not find public exponent, not a valid "
                       "key.\n");
                return 0;
            }
        }
        if (pub_exp != 0) {
            printf("%08x: Key: %i bits, public exponent %i.\n", offset,
                   (modlength - 1) * 8, pub_exp);
            return end;
        } else {
            return 0;
        }
    } else {
#if DEGUG
        printf("Invalid key found.");
#endif

        return 0;
    }
}
/*
 * Output DER information at offset 'offs'.
 */
void output_der(unsigned char *buffer, int offs, size_t size, long *count) {
    char filename[15];
    sprintf(filename, "privkey-%02li.der", *count);
    FILE *fp = fopen(filename, "wb");
    if (fp == NULL) {
        perror("fopen()");
        fprintf(stderr, "Failed to open %s.\n", filename);
        exit(-1);
    } else {
        fwrite(&buffer[offs], 1, size, fp);
        printf("Wrote key to file %s.\n", filename);
    }

    fclose(fp);
}

