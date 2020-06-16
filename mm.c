/*
 * Each allocated payload in the heap has a header preceeding it and a footer
 * following it, both containing the size and state of allocation (free or
 * alloced) of the block. 
 * To increase throughput:
 * --- uses an explicit free list in which free blocks have pointers to previous
 *     and next free blocks in the list. This free list is used in a "first fit"
 *     algorithm. Searches free list to find the first existing free block of 
 *     memory large enough to meet the malloc request, without having to go 
 *     through all of the heap.
 * --- Blocks are inserted into the free list using FIFO: insertion  at the 
 *     beginning of the free list.
 * To increase memory utilization:
 * --- uses splitting of free blocks that fit and 
 *     will result in a free block that meets the minimum size requirement 
 *     i.e. room for a header, footer, previous pointer, and next pointer.
 * --- uses coalescing on free() to combine adjacent free blocks into
 *     a contiguous free block.   
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>

#include "mm.h"
#include "memlib.h"

/* If you want debugging output, use the following macro.  When you hand
 * in, remove the #define DEBUG line. */
/*#define DEBUG*/
#ifdef DEBUG
# define dbg_printf(...) printf(__VA_ARGS__)
#else
# define dbg_printf(...)
#endif


/* do not change the following! */
#ifdef DRIVER
/* create aliases for driver tests */
#define malloc mm_malloc
#define free mm_free
#define realloc mm_realloc
#define calloc mm_calloc
#endif /* def DRIVER */

#define ALIGNMENT (2 * sizeof(size_t))

typedef struct {
  size_t header;
    /*
     * We don't know what the size of the payload will be, so we will
     * declare it as a zero-length array.  This allow us to obtain a
     * pointer to the start of the payload.
     */
  uint8_t payload[]; 
} block_t;

typedef struct {
  size_t footer;
} footer_t;


typedef struct free_block_t{
  size_t header; 
  struct free_block_t *prev;
  struct free_block_t *next;
  
} free_block_t;

free_block_t *head = NULL;  


footer_t *get_footer(size_t size, block_t *block) {
  footer_t *foot =  (footer_t *) (((uint8_t *) block) + (size - sizeof(footer_t)));
  return foot;
}

footer_t *get_prev_footer(block_t *block) {
  return (footer_t *) (((uint8_t *) block) - sizeof(footer_t)); 
}


block_t *get_prev_header(size_t prev_size, block_t *block) {
  return  (block_t *) (((uint8_t *) block) - prev_size);
}

void set_free(block_t *block, footer_t *footer) {
  footer->footer -= 0x1;
  block->header -= 0x1;
}

block_t *get_header(void *payload) {
  return (block_t *) ( ((uint8_t *) payload) - sizeof(block_t));
}


static size_t round_up(size_t size, size_t n) {
    return (size + n - 1) / n * n;
}

static size_t get_size(block_t *block) {
    return block->header & ~0x1;

}

static size_t get_size_footer(footer_t *footer) {
  return footer->footer & ~0x1;
}

static bool is_allocated_footer(footer_t *footer) {
  return footer->footer & 0x1;
}

static bool is_allocated(block_t *block) {
  return block->header & 0x1;
  
}

block_t *get_next_header(size_t size, block_t *block) {
  return (block_t *) (((uint8_t *) block) + size); 
}



static void set_header_footer(block_t *block, footer_t *footer, size_t size,
			      bool is_allocated) {
    block->header = size | is_allocated;
    footer->footer = block->header;
}

/* Removing a free block from the free list */
void remove_free_block(free_block_t *f_block) {
  free_block_t *prev_block = f_block->prev;
  free_block_t *next_block = f_block->next;
  /* If f_block is not at the head of the free list*/
  if (prev_block) {
    prev_block->next = next_block;
  }
  /* First block of free list*/ 
  else {
    head = next_block; 
  }
  /* If f_block is not at the tail of the free list*/
  if (next_block) {
    next_block->prev = prev_block;
  }
}

/* Adding a free block to the free list */
/* FIFO - First in first out */
void add_free_block(free_block_t *f_block){
  if (head) {
    head->prev = f_block;
    f_block->next = head;
    head = f_block;
  }
  else {
    head = f_block;
    f_block->next = NULL;
  }
  f_block->prev = NULL;
}


/* print_block - prints information about the memory block for debugging*/
void print_block(block_t *block, size_t intended_size) {
  size_t size = get_size(block);
  footer_t *footer = get_footer(size, block);
  printf("Intended_size: %zu\n", intended_size);
  printf("Is allocated: %u\n", is_allocated(block));
  printf("Size based on header: %zu\n", get_size(block) );
  printf("Size based on footer: %zu\n", get_size_footer(footer));
  printf("Address of header: %p\n" , block);
  printf("Address of footer: %p\n", footer);
  
}


/*
 * mm_init - Called when a new trace starts.
 */
int mm_init(void) {
  void *ptr  = mem_sbrk(ALIGNMENT - offsetof(block_t, payload));
  head = NULL;
  
  if ((long) ptr < 0) {
    return -1;
  }
  return 0;
}

/*
 * split - takes size of desired block and curr_block that is too big
 * returns block pointer to new appropriately sized split block
 */
block_t *split(size_t size, block_t *curr_block) {
  dbg_printf("\nSPLIT: %ld, block-to-split: %ld\n", size, get_size(curr_block));

  block_t* left_block = curr_block;
  block_t* right_block = (block_t *) (((uint8_t *)curr_block) + size);
  size_t right_size = get_size(curr_block) - size;
  
  footer_t *right_footer = get_footer(right_size, right_block);
  footer_t *left_footer = get_footer(size, curr_block);

  /* Left block is the newly alloced block */
  set_header_footer(left_block, left_footer, size, true);
  set_header_footer(right_block, right_footer, right_size, false );

  /* Remove old block from free list*/
  remove_free_block((free_block_t *) curr_block);
  
  /* Add right block to free list */
  add_free_block((free_block_t *) right_block);
  
  return left_block;
}



	       
/*
 * find_fit - Returns a pointer to a block_t of large enough size in heap memory
 * spliting when necessary. Returns NULL if no such pointer found.
 * This uses first fit.
 */
block_t *find_fit(size_t size) {
  free_block_t *f_curr_block = head;
  while (f_curr_block) {
    block_t * curr_block = (block_t *) f_curr_block;
    size_t curr_size = get_size(curr_block);

    /* Large enough free block found*/
    if (curr_size >= size) {
      dbg_printf("FOUND_FIT\n");

      /* Splits only if resulting size of split block would be: 
       * >= sizeof(free_block_t) + sizeof(footer_t) - makes room for
       * prev and next pointers should it be freed later */
      if (curr_size - size >= sizeof(free_block_t) + sizeof(footer_t)) {
	return split(size, curr_block);
      }
      /* Block can't be split*/
      else {
	remove_free_block(f_curr_block);
	set_header_footer(curr_block, get_footer(curr_size, curr_block),
			  curr_size, true);
	return curr_block;
      } 
    }
    f_curr_block = f_curr_block->next;							
  }
  return NULL;
}


/*
 * malloc - Allocate a block by searching for a free block in the heap and 
 * incrementing the brk pointer if no fitting free block is found.
 * Always allocate a block whose size is a multiple of the alignment.
 */
void *malloc(size_t size) {
  dbg_printf("\nMALLOC: %ld\n", size);

  /* free_block_buffer ensures that there is room for a prev and next pointers
     after the memory is freed */
  size_t free_block_buffer = 0;
  if (2*sizeof(free_block_t *) > size) {
    free_block_buffer = 2*sizeof(free_block_t *) - size;
  }
  
  size_t total_size = round_up(sizeof(block_t) + sizeof(footer_t) + size +
			       free_block_buffer,
			       ALIGNMENT); 
  block_t *malloc_block  = find_fit(total_size);

  /* No existing fitting block in heap */
  if (!malloc_block) {
    malloc_block = mem_sbrk(total_size);
    /* If sbrk failed i.e. no more heap memory available */
    if ((long) malloc_block < 0) {
      return NULL;
    }
    footer_t* footer = get_footer(total_size, malloc_block);
    set_header_footer(malloc_block, footer, total_size, true);
  }
  /*mm_checkheap(__LINE__);*/
  return malloc_block->payload;
}


/*
 * coalesce - Combines left and right free blocks into a single free block 
 */
block_t* coalesce(block_t *left, block_t *right) {
  dbg_printf("COALESCE\n");
  size_t total_size = get_size(left) + get_size(right);
  block_t *new_block = left;
  footer_t *new_footer = get_footer(get_size(right), right);
  
  /* is allocated = false, bc coalescing only in free() */
  set_header_footer(new_block, new_footer, total_size, false);
  return new_block;
}

/*
 * free - Sets the block containing the payload at the ptr as unallocated.
 * Coalesces if there exists an adjacent free block in memory at either side of the
 * given block.
 */
void free(void *ptr) {
  if (!ptr) {
    return;
  }
  dbg_printf("\nFREE\n");
  block_t *curr_block = get_header(ptr);
  size_t curr_size = get_size(curr_block);
  footer_t *footer = get_footer(curr_size, curr_block);

  
  /* Set the last bit of footer and header to 0 */
  set_free(curr_block, footer);
  
  footer_t *prev_footer = NULL;
  /*If curr_block is not the first block in the heap */
  if (curr_block != mem_heap_lo() + 8) {
    prev_footer = get_prev_footer(curr_block);
  }

  block_t *next_header = NULL;
  /* If cur_block is not the last block in the heap*/
  if (((uint8_t *) curr_block) + curr_size != mem_heap_hi() + 1) {
    next_header = get_next_header(curr_size, curr_block);
  }
  
  block_t *coalesced_left;
  /* Coalesce to the left*/
  if (prev_footer && !is_allocated_footer(prev_footer)) {
    size_t prev_size = get_size_footer(prev_footer);
    block_t * prev_header = get_prev_header(prev_size, curr_block);
    remove_free_block((free_block_t *)  prev_header);
    coalesced_left = coalesce(prev_header, curr_block);
  }
  /* No coalescing: left block is allocated or doesn't exist */
  else {
    coalesced_left = curr_block; 
  }

  block_t *total_coalesced;
  /* Coalesce to the right */
  if (next_header && !is_allocated(next_header)) {
    remove_free_block((free_block_t *) ((void *) next_header));
    total_coalesced = coalesce(coalesced_left, next_header);
  }
  /* No coalescing: right block is allocated or doesn't exist */
  else {
    total_coalesced = coalesced_left;
  }

  add_free_block( (free_block_t *) ((void *) total_coalesced));
}



/*
 * realloc - Change the size of the block by mallocing a new block,
 *      copying its data, and freeing the old block.
 **/
void *realloc(void *old_ptr, size_t size) { 
  /* If size == 0 then this is just free, and we return NULL. */
  if (size == 0) {
    free(old_ptr);
    return NULL;
  }
  /* If old_ptr is NULL, then this is just malloc. */
  if (!old_ptr) {
    return malloc(size);
  }

  dbg_printf("\nREALLOC: %p, %zu", (block_t *)(((uint8_t *) old_ptr) - sizeof(block_t)), size ); 
  void *new_ptr = malloc(size);

  /* If malloc() fails, the original block is left untouched. */
  if (!new_ptr) {
    return NULL;
  }

  /* Copy the old data. */
  block_t *block = old_ptr - offsetof(block_t, payload);
  size_t old_size = get_size(block);
  if (size < old_size) {
    old_size = size;
  }
  memcpy(new_ptr, old_ptr, old_size);

  /* Free the old block. */
  free(old_ptr);

  return new_ptr;

}


/*
 * calloc - Allocate the block and set it to zero.
 */
void *calloc(size_t nmemb, size_t size) {
  dbg_printf("CALLOC\n");
  size_t bytes = nmemb * size;
  void *new_ptr = malloc(bytes);

  /* If malloc() fails, skip zeroing out the memory. */
  if (new_ptr) {
    memset(new_ptr, 0, bytes);
  }

  return new_ptr;
}


void mm_checkheap(int verbose) {
  
  block_t *curr_block = mem_heap_lo() + 8;

  /* A check if the previous block in the heap was free*/
  bool is_last_free = 0;

  /* Number of free blocks according to the heap, and according to
     the free list*/
  uint64_t heap_num_free = 0;
  uint64_t f_num_free = 0;


  /* Loop through heap */
  while (curr_block < (block_t *) mem_heap_hi()) {
    
    size_t size = get_size(curr_block);
    if ((uint64_t)curr_block->payload % ALIGNMENT != 0) {
	printf("Address allignment wrong: line %d\n", verbose);
	printf("Address: %lx\n", (uint64_t) curr_block->payload);
	exit(1);
    }
    if (!(get_footer(size, curr_block)->footer == curr_block->header)) {
      printf("Footer and header do no match: line %d\n", verbose);
      printf("%zu\n",get_footer(size, curr_block)->footer);
      printf("%zu\n", curr_block->header);                
      exit(1);
    }
    if (size < sizeof(free_block_t) + sizeof(footer_t)) {
      printf("Size is smaller than minimum size\n: line %d", verbose);
      exit(1);
    }
    if (size % ALIGNMENT != 0) {
      printf("Size is not a multiple of alignment\n: line %d", verbose);
      exit(1);
    }

    if (curr_block->payload < (uint8_t *) mem_heap_lo() + ALIGNMENT ||
	curr_block->payload > (uint8_t *) mem_heap_hi()) {
      printf("Payload is outside bounds of heap: line %d\n", verbose);
      printf("Address of payload %p\n", curr_block->payload);
      printf("Address of mem_heap_hi %p\n", mem_heap_hi());
      printf("Address of mem_heap_lo + ALLIGNMENT %p\n",
	     (uint8_t *) mem_heap_lo() + ALIGNMENT);
      exit(1);
    }
    
    if (is_last_free && !is_allocated(curr_block)) {
      printf("There are two adjacent free blocks: line %d\n", verbose);
      exit(1);
    }
    is_last_free = !is_allocated(curr_block);

    /* curr_block is a free block */
    if (!is_allocated(curr_block)) {
      heap_num_free ++;
      free_block_t *f_curr_block = (free_block_t *)((void *)curr_block);
      free_block_t *prev_block = f_curr_block->prev;
      free_block_t *next_block = f_curr_block->next;
	
      if (next_block && next_block->prev != f_curr_block) {
	printf("Next's previous is not equal to Current: line %d\n", verbose);
	exit(1);
      }

      if(prev_block && prev_block->next != f_curr_block) {
	printf("Previous's next is not equal to Current: line %d\n", verbose);
	exit(1);
      }
    }
    
    curr_block = get_next_header(size, curr_block);
  }

  /* Loop through free list */
  free_block_t *f_curr = head;
  while (f_curr) {
    if ((uint8_t *) f_curr < (uint8_t *) mem_heap_lo()
	 || (uint8_t *)f_curr > (uint8_t *) mem_heap_hi()) {
      printf("Free list pointer not between mem_heap_lo and mem_heap_hi: line %d\n",
	     verbose);
      printf("Free block address: %p\n", f_curr);
      printf("Mem heap lo: %p\n", mem_heap_lo());
      printf("Mem heap hi: %p\n", mem_heap_hi());      
      exit(1);
    }
    f_num_free++;
    f_curr = f_curr->next;
  }

  if (f_num_free != heap_num_free) {
    printf("Number of free blocks inconsistent: line %d\n", verbose);
    printf("Num free according free list: %lu\n", f_num_free);
    printf("Num free according heap list: %lu\n", heap_num_free);    
    exit(1);
  }
    
  
    
}
