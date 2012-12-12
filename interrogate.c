/* ==========================================================================
 * interrogate.c
 *
 * Structural and entropy-based search for crypto keys in binary files or
 * memory dumps.
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

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <math.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#else
#include <unistd.h>
#endif

#include "interrogate.h"

/*
 * Main search method.
 *
 * Reads entire file (memory dump) into memory and searches file for 
 * cryptographic keys. Dispatches appropriate searching method based on user
 * input (e.g., the switches set at the command line. Also prints some 
 * headers for entropy searches.
 */
void keysearch(interrogate_context *ctx, unsigned char *buffer) {

	printf("Success, starting search.\n\n");

	if ((ctx->keytype == NO_KEYTYPE)) {
		printf(" Interval            | Size     | Windows | %s\n",
				(ctx->naivemode) ? "Entropy" : "Byte Count");
	}
	printf("----------------------------------------"
		"----------------------------------------\n");

	/* Set filelen to be the interval ending point if interval mode is
	 * set */
	if (ctx->interval)
		ctx->filelen = ctx->to;

	/* Search */
	switch (ctx->keytype) {
	case RSA:
		rsa_search(ctx, buffer);
		break;
	case AES:
		aes_search(ctx, buffer);
		break;
	case SERPENT:
		serpent_search(ctx, buffer);
		break;
	case TWOFISH:
		twofish_search(ctx, buffer);
		break;
        case TWOFISH_TC:
            twofish_search_old(ctx, buffer);
            break;
        case RSAWIN:
            rsa_win_search(ctx, buffer);
            break;
	default:
		if (ctx->quickmode) {
			quicksearch(ctx, buffer);
		} else {
			search(ctx, buffer);
		}
		break;
	}

	free(buffer);
}

/* =============================================================
 * Search functions for RSA, AES, SERPENT and TWOFISH key types.
 * =============================================================
 */

void rsa_search(interrogate_context *ctx, unsigned char *buffer) {
	int i;

	/* Calculate der-encoding parameters like lenght of data blob etc.
	 * according to PKCS #8 */
	int FLAG1 = 0x30;
	int FLAG2 = 0x82;

	/* Set interval parameter */

	if (ctx->interval)
		ctx->filelen = ctx->to;

	for (i = ctx->from; i < ctx->filelen - 1; i += 2) {
		unsigned char c1, c2, c3;
		int foundAt = -1;
		c1 = (unsigned char) buffer[i];
		c2 = (unsigned char) buffer[i + 1];
		if (c1 == FLAG1) {
			if (c2 == FLAG2) {
				foundAt = i;
			}
		} else if (c2 == FLAG1) {
			c3 = (unsigned char) buffer[i + 2];
			if (c3 == FLAG2) {
				foundAt = i + 1;
			}
		}
		if (foundAt != -1) {
			if (ctx->verbose)
				printf("Signature hit...");
			int derLength;
			if ((derLength = parse_der(buffer, foundAt))) {
				ctx->count++;
				output_der(buffer, foundAt, derLength, &(ctx->count));
				//Skip the bytes containing the key
				i += derLength;
			} else {
				if (ctx->verbose)
					printf("not a key.\n");
			}
		}
	}
}

void rsa_win_search(interrogate_context *ctx, unsigned char *buffer) {
    int i;
    int R = 0x52;
    int S = 0x53;
    int A = 0x41;
    int TWO = 0x32;

    if (ctx->interval)
        ctx->filelen = ctx->to;

    for (i = ctx->from; i < ctx->filelen - 1; i++) {
        if (buffer[i] == R && buffer[i+1] == S && buffer[i+2] == A && buffer[i+3] == TWO)
            printf("Signature hit at %.8x\n", i);
    }
}

void aes_search(interrogate_context *ctx, unsigned char *buffer) {
	int i;

	/* Set key schedule sizes */
	int kssize = 176;
	if (ctx->keysize == 192) {
		kssize = 208;
	} else if (ctx->keysize == 256) {
		kssize = 240;
	}

	unsigned char *ks = malloc(kssize * sizeof(unsigned char));

	for (i = ctx->from; i < ctx->filelen - kssize; i++) {
		/* Copy a chunk of data from buffer, expand it using AES key
		 * schedule routines */
		ks = memcpy(ks, &buffer[i], kssize);
		if ((ctx->keysize == 128))
			expand_key(ks);
		else if ((ctx->keysize == 192))
			expand_key_192(ks);
		else
			expand_key_256(ks);
		/* Compare expanded key schedule to the data proceeding the chunk */
		if (memcmp(ks, &buffer[i], kssize) == 0) {
			ctx->count++;
			printf("Found (probable) AES key at offset %.8x:\n", i);
			print_hex_array(ks, ctx->keysize / 8, 16);
			printf("Expanded key:\n");
			print_hex_array(ks, kssize, 16);
		}
	}

}

void serpent_search(interrogate_context *ctx, unsigned char *buffer) {
	int i;
	/* Key schedule size for SERPENT is always 560 bytes*/
	int kssize = 560;

	unsigned char *ks = calloc(kssize, sizeof(unsigned char));

	/* Iterate byte by byte through memory */
	for (i = ctx->from; i < ctx->filelen - kssize; i++) {
		/* Copy chunk of data from buffer, and expand with SERPENT key
		 * schedule expansion */
		ks = memcpy(ks, &buffer[i], kssize);
		serpent_set_key(ks, ctx->keysize, ks);
		/* Compare result to the original buffer data */
		if (memcmp(ks, &buffer[i], kssize) == 0) {
			ctx->count++;
			printf("Found (probable) SERPENT key at offset %.8x:\n", i);
			print_hex_array(ks, ctx->keysize / 8, ctx->keysize / 8);
			printf("Expanded key:\n");
			print_hex_array(ks, kssize, 16);
		}
	}
}

void twofish_search(interrogate_context *ctx, unsigned char *buffer) {
	int i, firstrun, lastrun;
    /* Override user selected window size */
    ctx->wsize = 4096;
	
	/* Check that the input file can actually hold a full key schedule */
	size_t tfi_size = sizeof(twofish_tc); // Largest key schedule
	if (ctx->filelen < tfi_size) {
		fprintf(stderr, "Filesize too small to hold a TwoFish key.\n");
		return;
	}
	
	int run[TF_RUNS];
	firstrun = lastrun = 0;
    /* Check first window and initialize */
    i = ctx->from;
	runs(ctx, &buffer[i], run, TF_RUNS, &firstrun, &lastrun);
    if (is_mk_tab(run)) {
        validate_tf_ks(ctx, buffer, i);
    }
    
    /* Check each sequential window */
	for (; i < ctx->filelen; i++) {
		runs_opt(ctx, &buffer[i], run, TF_RUNS, &firstrun, &lastrun);
        if (is_mk_tab(run)) {
            validate_tf_ks(ctx, buffer, i);
        }
	}
	
}

/*
 * Deprecated. Old twofish key search method. Use twofish_search() instead.
 * This method will only work for truecrypt-like implementations.
 */
void twofish_search_old(interrogate_context *ctx, unsigned char *buffer) {
	twofish_tc *instance = malloc(sizeof(twofish_tc));
	int i;
	float entropy;

	/* Check that the input file can actually hold a full key schedule */
	size_t tfi_size = sizeof(twofish_tc);
	if (ctx->filelen < tfi_size) {
		fprintf(stderr, "Filesize too small to hold a TwoFish key.\n");
		return;
	}
	
	/* For each byte in memory, interpret it as the start of a
	 * twofish_nstance struct, and check whether it has 2, 3 or 4 as the 
	 * twofish  key_len. If so, perform structural and statistical tests to 
	 * verify that it is a valid TWOFISH key schedule */
	for (i = ctx->from; i < ctx->filelen - tfi_size; i++) {
		instance = (twofish_tc *)&buffer[i];
		switch (instance->k_len) {
		case 2:
			/* Potential 128-bit key.
			 * If key_len is 2, only the two leftmost s_keys are non-zero */
			if ((instance->s_key[2] == 0) && (instance->s_key[3] == 0)
					&& (instance->l_key[0] != 0)) {
				entropy = ent(ctx, (unsigned char *)instance->mk_tab,
						sizeof(instance->mk_tab));
				/* The entropy of mk_tab is awlways maximum (8) */
				if (entropy == 8) {
					/* Calculate entropy of the l_keys */
					entropy = ent(ctx, (unsigned char *)instance->l_key,
							sizeof(instance->l_key));
					if ((entropy > 6) && (entropy < 7.2)) {
						ctx->count++;
						printf("Found (probable) TwoFish key at "
							"offset %.8x:\n", i);
						printf("Expanded key:\n");
						print_hex_words((unsigned int *)instance, 
								tfi_size / 4, 4);
					}
				}
			}
			break;
		case 3:
			/* Potential 198-bit key.
			 * If key_len is 3, only the leftmost s_key is non-zero */
			if ((instance->s_key[3] == 0) && (instance->l_key[0] != 0)) {
				entropy = ent(ctx, (unsigned char *)instance->mk_tab,
						sizeof(instance->mk_tab));
				/* The entropy of mk_tab is awlways maximum (8) */
				if (entropy == 8) {
					/* Calculate entropy of the l_keys */
					entropy = ent(ctx, (unsigned char *)instance->l_key,
							sizeof(instance->l_key));
					if ((entropy > 4)) {
						ctx->count++;
						printf("Found (probable) TwoFish key at "
							"offset %.8x:\n", i);
						printf("Expanded key:\n");
						print_hex_words((unsigned int *)instance, 
								tfi_size / 4, 4);
					}
				}
			}
			break;
		case 4:
			/* Potential 256-bit key */
			entropy = ent(ctx, (unsigned char *)instance->mk_tab,
					sizeof(instance->mk_tab));
			if ((entropy == 8)) {
				/* Calculate entropy of the l_keys */
				entropy = ent(ctx, (unsigned char *)instance->l_key,
						sizeof(instance->l_key));
				if ((entropy > 6) && (entropy < 7.2)) {
					/* Calculate entropy of the l_keys */
					entropy = ent(ctx, (unsigned char *)instance->s_key,
											sizeof(instance->s_key));
					ctx->count++;
					printf("Found (probable) TwoFish key at "
						"offset %.8x:\n", i);
					printf("Expanded key:\n");
					print_hex_words((unsigned int *)instance, 
							tfi_size / 4, 4);
				}
			}
			break;
		}
	}
}

/* ------------------------------------------
 * Search functions for entropy-based search.
 * ------------------------------------------
 */

void search(interrogate_context *ctx, unsigned char *buffer) {
	int i, found, start, end;
	float entropy, cent;
	found = FALSE;
	entropy = cent = 0.0;
	start = ctx->from;

	//TODO: Change from continous sections to only windows of entropy
	for (i = ctx->from; i < ctx->filelen - ctx->wsize; i++) {
		/* Calculate entropy (if naivemode) or simply count unique bytes */
		entropy = (ctx->naivemode) ? ent(ctx, &buffer[i], ctx->wsize)
				: countbytes(ctx, &buffer[i]);
		/* Print value to file if the -p switch is set */
		if (ctx->output_fp != NULL)
			print_to_file(ctx->output_fp, entropy);

		if (entropy >= ctx->threshold) {
			if (!found) {
				start = i;
				ctx->count++;
				found = TRUE;
			}
			cent += entropy;
		} else {
			if (found) {
				end = i + ctx->wsize - 1; /* Ended at previous round */
				int bytes = end - start;
				float numblocks = (float) bytes / ctx->wsize;
				printblobinfo(start, end, bytes, numblocks, cent / (bytes
						- ctx->wsize + 1));
				cent = 0;
				found = FALSE;
			}
		}
	}

	/* If found is true here, we found something in the last round, print
	 * it */
	if (found) {
		end = i + ctx->wsize;
		int bytes = end - start;
		float numblocks = (float) bytes / ctx->wsize;
		printblobinfo(start, end, bytes, numblocks, 
				cent / (bytes - ctx->wsize));
	}

}

void quicksearch(interrogate_context *ctx, unsigned char *buffer) {
	/* Move window over file and calculate entropy for each window
	 * position */
	int i;
	float entropy = 0.0;
	int eof= FALSE;
	int found= FALSE;
	float cent = 0; /* Cumulative entropy */
	int start, end;
	start = i = ctx->from;
	int oldwsize = ctx->wsize;

	while (!eof) { /* Last round, make sure the window fits */
		if ((i >= ctx->filelen - ctx->wsize)) {
			eof = TRUE;
			ctx->wsize = ctx->filelen - i;
		}
		/* The end of the current search window */
		end = i + ctx->wsize;

		/* Calculate entropy (if naivemode) or simply count unique bytes */
		entropy = (ctx->naivemode) ? ent(ctx, &buffer[i], ctx->wsize)
				: countbytes(ctx, &buffer[i]);
		/* Print value to file if the -p switch is set */
		if (ctx->output_fp != NULL)
			print_to_file(ctx->output_fp, entropy);

		if (entropy >= ctx->threshold) {
			/* If found is false, the last block did not contain high
			 * entropy. In that case, mark the start of a new block,
			 * increment block counter and set fount to true */
			if (!found) {
				start = i;
				ctx->count++;
				found = TRUE;
			}

			/* Accumulate total entropy */
			cent += entropy;

			if (eof) { // If this is the last round, print it right away
				int bytes = end - start;
				float numblocks = (float) bytes / oldwsize;
				printblobinfo(start, end, bytes, numblocks, 
						cent / numblocks);
			}
		} else {
			/* If found is true, the last block examined contained high
			 * entropy, but the current block did not. In that case
			 * the entropy blob has reached its end after the previous
			 * block, and we'll print its data. */
			if (found) {
				int prevend = end - ctx->wsize;
				int bytes = prevend - start;
				float numblocks = (float) bytes / oldwsize;
				printblobinfo(start, prevend, bytes, numblocks, cent
						/ numblocks);
				cent = 0;
				found = FALSE;
			}
		}
		i += ctx->wsize; // Increment counter, move wsize bytes each round
	}
	ctx->wsize = oldwsize; // Restore window size
}

/* -----------------------
 * Main program functions.
 * -----------------------
 */

/*
 * Prints usage and help info
 */
void help() {
	printf("Usage: interrogate [OPTION]... [FILE]...\n"
	"Search for cryptographic keys in the FILEs (memory dumps).\n"
	"\n"
	"  -a algorithm    search for keys of a certain type (algorithm).\n"
	"                    Valid parameters: aes, rsa, win-rsa, serpent,\n"
	"                    [tc-]twofish. Use the -k switch to specify AES\n"
        "                    key lengths (128, 198, or 256 bits). RSA keys are\n"
	"                    found independent of their length, while SERPENT\n"
	"                    and TWOFISH keys are required to be 256 bits.\n"
        "                    The rsa parameter specifies DER-encoded rsa keys,\n"
        "                    while win-rsa requires Private Key BLOB (Windows)\n"
        "                    structure.\n"
	"  -h                prints usage and help information (this message).\n"
	"  -i interval     only search within interval. Format of interval is\n"
	"                    from_offset:to_offset where the offset values\n"
	"                    are interpreted as hexadecimal values. Omitting\n"
	"                    one of the offsets will indicate the start or\n"
	"                    the end of the FILEs, respectively. Used with\n"
	"                    the -r switch, the interval will be interpreted\n"
	"                    as the virtual address space that are to be\n"
	"                    reconstructed.\n"
	"  -k keylength    length of key to be searched for (NB: in BITS)\n"
	"  -n                naive mode, calculates true entropy instead of\n"
	"                    counting unique bytes (which is the normal\n"
	"                    mode). This may be useful if you get bad quality\n"
	"                    results, but may yield some performance\n"
	"                    degradation.\n"
	"  -p filename     print entropy values for each window separated\n"
	"                    by newlines to file specified by filename. This\n"
	"                    may be used as input to plotting tools (gnuplot)\n"
	"                    WARNING: Slow and generates large files, one\n"
	"                    input byte maps to potentially six output bytes.\n"
	"  -q              quick mode, does not use overlapping windows. The\n"
	"                    larger the window size, the quicker. Use -w to\n"
	"                    specify window size.\n"
	"  -r CR3          reconstructs the virtual address space for the\n"
	"                    process at offset PDB. The PDB is the location of\n"
	"                    the page directory base, and can be found by\n"
	"                    scanning for EPROCESSes using PTfinder,\n"
	"                    Volatility or other similar tools. The\n"
	"                    regonstructed memory is written to file\n"
	"                    'pages', and are searched subsequently for\n"
	"                    keys. The -i option may be used to specify a\n"
	"                    virtual address space interval.\n"
	"  -t threshold    sets the entropy threshold (default = 7.0).\n"
	"  -w windowsize   sets the window size. Not compatible with the -a\n"
	"                    option.\n");
}

/*
 * Initializes the context of Interrogate.
 */
void initialize(interrogate_context *ctx) {
	ctx->keytype = NO_KEYTYPE; 			/* No keytype by default */
	ctx->keysize = 0; 					/* Size of key to (in bits) */
	ctx->wsize = WINDOWSIZE; 			/* Size of search window */
	ctx->nofs = NOFSYMBOLS; 			/* Size of our alphabet */
	ctx->threshold = THRESHOLD; 		/* Default entropy threshold */
	ctx->bitmode = FALSE; 				/* Bit-mode is false by default */
	ctx->naivemode = FALSE; 			/* Naive mode is false by default */
	ctx->quickmode = FALSE; 			/* Quickmode turned off by default */
	ctx->interval = FALSE; 				/* Interval turned off by default */
	ctx->verbose = FALSE; 				/* Verbose mode is per def false */
	ctx->from = ctx->to = 0; 			/* Interval is zero by default */
	ctx->cr3 = 0; 						/* Don't reconstruct (default) */
	ctx->filelen = 0; 					/* Zero file length */
	ctx->count = 0; 					/* Set key counter to zero */
}

/*
 * Main program, parse parameters and set context
 */
int main(int argc, char **argv) {
	int c; 										/* Stores argument options */
	int i; 								 		/* Counter */
	FILE *fp; 									/* Pointer to input file */
	interrogate_context *ctx = 
		malloc(sizeof(interrogate_context));	/* Program context */

	printf(
    "Interrogate  0.0.4 Copyright (C) 2008  Carsten Maartmann-Moe "
    "<carsten@carmaa.com\n"
    "This program comes with ABSOLUTELY NO WARRANTY; for details use `-h'.\n"
    "This is free software, and you are welcome to redistribute it\n"
    "under certain conditions; see bundled file licence.txt for details.\n\n"
			);
	
	initialize(ctx);

    /* Parse arguments and set options, see help() method for explaination */
    while ((c = getopt(argc, argv, "a:hi:k:np:qr:t:vw:")) != -1) {
        switch (c) {
        case 'a':
            if (strncmp(optarg, "aes", 3) == 0) {
                ctx->keytype = AES;
            } else if (strncmp(optarg, "rsa-win", 7) == 0) {
                ctx->keytype = RSAWIN;
            } else if (strncmp(optarg, "rsa", 3) == 0) {
                ctx->keytype = RSA;
            } else if (strncmp(optarg, "serpent", 7) == 0) {
                ctx->keytype = SERPENT;
                /* We only have support for 256-bit SERPENT keys */
                ctx->keysize = 256;
            } else if (strncmp(optarg, "twofish", 7) == 0) {
                ctx->keytype = TWOFISH;
                /* We only have support for 256-bit TWOFISH keys */
                ctx->keysize = 256;
            } else if (strncmp(optarg, "tc-twofish", 10) == 0) {
                ctx->keytype = TWOFISH_TC;
                /* We only have support for 256-bit Truecrypt TWOFISH keys */
                ctx->keysize = 256;
            } else {
                fprintf(stderr, "Invalid keytype.\n");
                help();
                exit(-1);
            }
            break;
        case 'h':
            help();
            exit(0);
        case 'i':
            ctx->interval = TRUE;
            /* Do ugly parsing of argument :-/ */
            char *to_ptr = strstr(optarg, ":"); // Find ':'
            *to_ptr = '\0'; // Replace with string terminator
            to_ptr++;
            /* Convert from hexadecimal ASCII */
            ctx->from = (int)strtol(optarg, (char**)NULL, 16);
            ctx->to = (int)strtol(to_ptr, (char **)NULL, 16);
            if (ctx->to < ctx->from && ctx->to != 0) {
                fprintf(stderr, "Error in interval, the start offset "
                        "is bigger than the end offset.\n");
                exit(-1);
            }
            break;
        case 'k':
            ctx->keysize = atoi(optarg);
            printf("Using key size: %i bits.\n", ctx->keysize);
            break;
        case 'n':
            ctx->naivemode = TRUE;
            printf("Using naive mode, searching for true entropy.\n");
            break;
        case 'p':
            ctx->output_fp = open_file(ctx, optarg, "w");
            break;
		case 'q':
			ctx->quickmode = TRUE;
			printf("Using quickmode.\n");
			break;
		case 'r':
			ctx->cr3 = (int)strtol(optarg, (char**)NULL, 16);
			break;
		case 't':
			ctx->threshold = atof(optarg);
			printf("Using entropy threshold: %f bits per symbol.\n",
					ctx->threshold);
			break;
		case 'v':
			ctx->verbose = TRUE;
			printf("Verbose mode.\n");
			break;
		case 'w':
			ctx->wsize = atoi(optarg);
			printf("Using window size: %i bytes.\n", ctx->wsize);
			break;
		case '?':
			if (optopt == 'c' || optopt == 'w') {
				fprintf(stderr, "Option -%c requires an "
				"argument.\n", optopt);
			} else if (isprint(optopt)) {
				fprintf(stderr, "Unknown option `-%c'.\n",
				optopt);
			} else {
				fprintf(stderr, "Unknown option character "
				"`\\x%x'.\n", optopt);
			}
			return 1;
		default:
			exit(-1);
		}
	}
	/* Check that the windowsize is reasonable */
	if (ctx->naivemode && (ctx->wsize < (ctx->nofs / 2))) {
		printf("WARNING: You're using a windowsize smaller than half of the "
			"number of symbols together with naive mode, this might not "
			"yield a good result. Try dropping -n.\n");
	}
	/* Check that keytypes match supported key lengths */
	switch (ctx->keytype) {
	case AES:
		if (!(ctx->keysize == 128 || 
				ctx->keysize == 192 || 
				ctx->keysize == 256)) {
			fprintf(stderr, "A key size of 128, 192 or 256 bits are "
			"required for AES search.\n");
			exit(-1);
		}
		break;
	case SERPENT:
		if (!(ctx->keysize == 256)) {
			fprintf(stderr, "A key size of 256 bits are required for "
			"SERPENT search.\n");
			exit(-1);
		}
		break;
	case TWOFISH:
		if (!(ctx->keysize == 256)) {
			fprintf(stderr, "A key size of 256 bits are required for "
			"TWOFISH search.\n");
			exit(-1);
		}
		break;
	}
    
	if ((!ctx->naivemode)
			&& (ctx->keytype == NO_KEYTYPE && ctx->threshold == 7)) {
		/* Set relaxed byte count threshold since the user didn't
		 * specify one*/
		ctx->threshold = floor((ctx->wsize / NOFSYMBOLS) * ctx->threshold
				* BCMOD);
		printf("WARNING: No -t option specified, bytecount threshold was "
			"set to  %f. This may yield inaccurate results.\n", 
			ctx->threshold);
	}

    /* The rest of the args are treated as files */
    if (optind < argc) {
        for (i = optind; i < argc; i++) {
            /* Check and open file for reading */
        	fp = open_file(ctx, argv[i], "rb");
            printf("Using input file: %s.\n", argv[i]);
            if (ctx->interval) {
                /* Check if intervals are out of bounds */
                if (ctx->from < 0) {
                    ctx->from = 0;
                    printf("WARNING: Interval out of bounds, changed it "
                           "for you:\n");
                }
                /* If the upper bound is too big, set it to filelenght */
                if (ctx->to > ctx->filelen) {
                    ctx->to = ctx->filelen;
                    /* If the lower bound is too low, set it to zero */
                    if (ctx->to < ctx->from)
                        ctx->from = 0;
                    printf("WARNING: Interval out of bounds, changed it "
                           "for you:\n");
                }
                /* If no upper bound is given, set it to filelength */
                if (ctx->to == 0) {
                    ctx->to = ctx->filelen;
                }
                printf("Searching in interval 0x%08X - 0x%08X.\n",
                       ctx->from, ctx->to);
            }
            
            unsigned char *buffer = 
                malloc(ctx->filelen * sizeof(unsigned char));
            buffer = read_file(ctx, fp);
            
            /* Reconstruct memory if the -r switch is on */
            if(ctx->cr3 != 0) {
            	printf("Reconstructing virtual memory for process with PDB "
                        "at %08x, please stand by...\n", ctx->cr3);
            	reconstruct(ctx, buffer);
            	printf("Using recontructed virtual memory file "
            			"'pages' for search.\n");
            	fp = open_file(ctx, "pages", "rb");
                buffer = 
                    realloc(buffer, ctx->filelen * sizeof(unsigned char));
            	buffer = read_file(ctx, fp);
            }
            
            /* Perform search */
            keysearch(ctx, buffer);

			/* Clean up */
			if (ctx->output_fp != NULL) {
				fclose(ctx->output_fp);
			}
			fclose(fp);
		}
		printf("\nA total of %li %s found.\n", ctx->count, (ctx->keytype
				== NO_KEYTYPE) ? "entropy blobs" : "keys");
		printf("Spent %li seconds of your day looking for the key.\n", 
				clock() / CLOCKS_PER_SEC);
	} else {
		fprintf(stderr, "Missing input file.\n");
		help();
	}
	free(ctx);
	return 0;
}
