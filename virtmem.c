/* =========================================================================
 * virtmem.c
 * 
 * Utility to reconstruct virtual memory from the Nonpaged Pool of a
 * process. Part of Interrogate
 * 
 * Author: Carsten Maartmann-Moe <carmaa@gmail.com>
 * =========================================================================
 */
#include <stdio.h>
#include <stdlib.h>

#include "interrogate.h"

/* Iterate through the virtual addresses in the Nonpaged Pool virtual
 * address space and fetch pages from the physical memory, using the
 * CR3 address as Page Directory base.
 */
void reconstruct(interrogate_context *ctx, unsigned char *buffer) {
    pte *pd, *pt;                     /* Page directory and table pointers */
    pte pd_entry, pt_entry;           /* Page directory and table entries */
    virtual_address *addr;            /* Virtual address */
    FILE *fp = fopen("pages", "wb");  /* Output file */
    unsigned int *frames;             /* Fetched page frame numbers */
    unsigned long this_pagesize;      /* The current pagesize (large page) */
    unsigned char *page;              /* Current page */
    unsigned int i, last_i, l_pc, pc; /* (Page) counters */
    unsigned int lim_low;             /* Lower virtual address space bound */
    unsigned int lim_high;            /* Upper virtual address space bound */

    pd = malloc(sizeof(pte) * 1024);
    pt = malloc(sizeof(pte) * 1024);
    addr = malloc(sizeof(virtual_address));
    long memorysize = ctx->filelen;
    l_pc = pc = last_i = 0;

    /* Assume standard pagesize */
    int pagesize = 4096;

    /* Allocate and zero out memory for already fetched pages db */
    frames = calloc(memorysize / pagesize, sizeof(unsigned int));

    /* The page directory is located at the offset pointed to by CR3 */
    pd = (pte *)&buffer[ctx->cr3];

    if (ctx->interval) {
        lim_low = ctx->from;
        lim_high = ctx->to;
        ctx->interval = FALSE; // To prevent interval-search in main
    } else {
        /* A bit more dirty; use the whole virtual address space :-/ */
        lim_low = 0x00000000;
        lim_high = 0xffffffff;
    }
    printf("Reconstructing virtual memory from %08x to %08x. To change "
           "this, use the -i switch.\n", lim_low, lim_high);

    /* Large pages are only available with physical memory size > 255 MB */
    int large_pages = (memorysize > (255 * 1024));
    if (large_pages) {
        page = malloc(pagesize * 1024 * sizeof(unsigned char)); // 4 MB pages
    } else {
        page = malloc(pagesize * sizeof(unsigned char)); // 4 KB pages
    }

    for (i = lim_low; i < lim_high; i += pagesize) {
        /* Break if 'i' wraps around e.g. integer overflow */
        if (i < last_i)
            break;

        addr = (virtual_address *)&i;
        pd_entry = pd[addr->pd_index];
        /* Skip NULL entries */
        if (!*(unsigned int *)&pd_entry)
            continue;

        /* The target page table is found via the pfn of the pde */
        unsigned long pde_offset = pd_entry.pfn * pagesize;
        /* Check that the page is in memory, and that it is within bounds */
        if ((pde_offset < memorysize) &&
                pd_entry.valid) {
            pt = (pte *)&buffer[pde_offset];
            if (!pt)
                continue; // Null pointer
            pt_entry = pt[addr->pt_index];
            /* Skip NULL entries */
            if (!*(unsigned int *)&pt_entry)
                continue;
        }

        unsigned long pte_offset = pt_entry.pfn * pagesize;
        /* Check that the page is in memory, and that it is within bounds */
        if ((pte_offset < memorysize) &&
                pt_entry.valid) {
            if (!frames[pt_entry.pfn]) { // If the page (frame) is new
                /* Mark page as found, and fetch from buffer */
                frames[pt_entry.pfn] = 1;
                page = &buffer[pte_offset];

                if (ctx->verbose) {
                    print_pte(addr, pd, &pd_entry, pt, &pt_entry, page);
                }

                /* Set proper pagesize for current page */
                if (pt_entry.large_page && large_pages) {
                    l_pc++;
                    this_pagesize = pagesize * 1024;
                } else {
                    pc++;
                    this_pagesize = pagesize;
                }

                /* Place each page fetched sequentially in a new file */
                fwrite(page, sizeof(unsigned char), this_pagesize, fp);
            }
        }
        last_i = i; // Update the last value of 'i'
    }
    printf("Wrote %i pages to disk, %i normal and %i large, a total of "
           "%.2f MB.\n", l_pc + pc, pc, l_pc, 
           ((double)ftell(fp) / (1024*1024)));
    fclose(fp);
}

void print_pte(virtual_address *addr, pte *pd, pte *pde, pte *pt, pte *pte,
               unsigned char *page) {
    printf( "Vitual address: %08x\n"
            "PD index:       %08x -> Byte offset:       %08x\n"
            "PDE value:      %08x -> Page frame number: %08x\n"
            "PT index:       %08x -> Byte offset:       %08x\n"
            "PTE value:      %08x -> Page frame number: %08x\n"
            "Flags:          %c%c%c%c%c%c%c%c%c%c\n"
            "First 16 bytes of page: ",
            *(unsigned int *)addr, addr->pd_index, addr->pd_index * 4,
            *(unsigned int *)&pde, pde->pfn,
            addr->pt_index, addr->pt_index * 4,
            *(unsigned int*)&pte, pte->pfn,
            (pte->copy_on_write)?'C':'-', (pte->global)?'G':'-',
            (pte->large_page)?'L':'-', (pte->dirty)?'D':'-',
            (pte->accessed)?'A':'-', (pte->cache_disabled)?'N':'-',
            (pte->write_through)?'T':'-', (pte->owner)?'U':'K',
            (pte->write)?'W':'R', (pte->valid)?'V':'-'
          );
    /* Print first 16 bytes of page */
    print_hex_array(page, 16, 16);
}

