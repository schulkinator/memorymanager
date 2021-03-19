#ifndef MEMORY_MANAGER_H_INCLUDED
#define MEMORY_MANAGER_H_INCLUDED

// For quick disabling of memory management just comment this line
#define ENABLE_MEMORY_MANAGEMENT

#include <new>
#include <atomic>
#include <mutex>
#include <unordered_map>
// The Memory Manager handles preventing fragmentation of memory for systems with a lack of good virtual memory management.
// It globally overrides the new and delete c++ operators (but not malloc/free).
// It values performance speed over optimal space efficiency (some space will be wasted).
// It does this by allocating contiguous arenas of memory of geometrically 
// increasing sizes (doubling powers of two) based on allocation size.
// Based on my tests on an AMD Ryzen Threadripper machine running windows 10 64bit & visual studio 2019,
// it is about 3x slower than standard allocation, but 2x faster than standard deallocation.

// Terminology: 
// "Thread Sandbox" - A thread sandbox is simply the working space of memory that only one specific thread can touch 
// "Arena" - A contiguous chunk of memory which contains individual cells of memory
// "Cell" - A single block of memory that is intended to be the smallest atomic unit for allocation managed by the memory manager. 
//          aka. the blocks used by outside code

#ifdef ENABLE_MEMORY_MANAGEMENT
void* operator new(size_t size);
void* operator new(size_t size) throw(std::bad_alloc);
void* operator new[](size_t size);
void* operator new[](size_t size) throw(std::bad_alloc);

void operator delete(void* p);
void operator delete(void*, size_t size);
void operator delete(void*, size_t size) throw();
void operator delete[](void*, size_t size);
void operator delete[](void* p, size_t size) throw();
void operator delete[](void* p);
#endif

class MemoryManager {
public:

  struct ArenaCollection;
  struct DeallocRequest;

  // A thread sandbox is simply the working space that only one specific thread can touch 
  struct ThreadSandboxNode {
    unsigned int thread_id;
    // the number of different sizes of arenas we have
    // this is essentially the length of the arenas array below
    unsigned int num_arena_sizes;
    // arenas is a 1-dimensional array of pointers where the first dimension represents arena size (powers of two doubling every time)
    // the contents of which is a pointer to the head of a linked list of arenas
    ArenaCollection** arenas;
    ThreadSandboxNode* next;
    // other threads can request to make a deallocation on this thread
    // processing of this queue only happens when new allocations are made on this thread  
    std::mutex dealloc_mutex;
    std::atomic<unsigned int> num_deallocs_queued;
    std::atomic<unsigned int> deallocs_capacity;
    DeallocRequest* dealloc_queue; // this is a dynamic array of dealloc requests (can resize and grow larger if capacity runs out)
  };

  struct ArenaHeader;

  // Holds a list of arenas inside it and pointers to arenas which have had recent allocations/deallocations 
  // in order to speed up finding arenas that have free cells in them
  struct ArenaCollection {
    // pointer back to the sandbox that owns this arena collection
    ThreadSandboxNode* sandbox;
    // all arenas in this collection will have the same size cells
    unsigned int cell_size_bytes;
    unsigned int num_arenas;
    ArenaHeader* first;
    // points to an arena which recently had a cell deallocation (meaning it probably has a free cell)
    ArenaHeader* recent_dealloc_arena;
    // points to an arena which recently had a cell allocation
    ArenaHeader* recent_alloc_arena;
  };

  // A contiguous chunk of memory which contains individual cells of memory
  struct ArenaHeader {
    // a pointer to the collection this arena is a part of
    ArenaCollection* arena_collection;
    unsigned int cell_size_bytes;
    unsigned int padding_size_bytes;
    // 64bit value each bit represents a cell of memory in the arena marking it as occupied or not
    // The lower-order bits in this value represent cells at the beginnning of the arena
    // the higher-order bits in this value represent cells at the end of the arena
    unsigned long long cell_occupation_bits;
    unsigned int num_cells_occupied;
    unsigned int cell_capacity;
    // arena_start will point to the start of the data arena (ie: the first cell)
    // it is already pointing to the aligned address past the padding (no need to offset past padding)
    unsigned char* arena_start;
    // arena_end will point to the last byte of the last cell in the arena
    unsigned char* arena_end;
    ArenaHeader* next;
    // just occupies 8 bytes as a guard and as an integrity verification
    unsigned long long dummy_guard;
  };

  // A single block of memory that is intended to be the smallest atomic unit for allocation managed by the memory manager.
  //          aka. the blocks used by outside code
  struct CellHeader {
    // pointer to this cell's arena header
    ArenaHeader* arena_header;
    // just occupies 8 bytes as a guard and as an integrity verification
    unsigned long long dummy_guard;
  };

  struct DeallocRequest {
    void* data;
    size_t size;
  };

  static void* Allocate(size_t size);
  static void Deallocate(void* data, size_t size);

  static ThreadSandboxNode* AllocateNewThreadSandbox(ThreadSandboxNode* tail_of_list, unsigned int thread_id);
  static inline ThreadSandboxNode* FindSandboxForThread(unsigned int thread_id, ThreadSandboxNode*& last_node);
  // alignment_bytes is the byte address alignment we desire, for example 4 or 8, or 16
  static ArenaHeader* AllocateArenaOfMemory(size_t cell_size_without_header_bytes, size_t alignment_bytes, ArenaCollection* arena_collection);

  static inline unsigned int CalculateCellSizeAndArenaIndexForAllocation(size_t allocation_size, unsigned int& arena_index);
  static inline unsigned int CalculateCellCapacityForArena(unsigned int cell_size, unsigned int max_arena_size, unsigned int max_cells_per_arena);

  // deallocate all thread memory and shut down
  static void ThreadShutdown();

  //There is one additional wrinkle: Even though we keep thread memory sandboxes separate, one thread may try to delete memory in another thread sandbox.
  //In this case we need put the delete request from the alien thread on a queue and then process it on the local thread at a later time.
  //Access to this queue MUST be synchronized with a mutex.
  // We operate with the observations:
  //a) often the object is freed by the same thread that had allocated it, and
  //b) when the object is deleted by a different thread, it does not interfere with all other threads, 
  //   but only with those that need to use the same pending requests list

  // Unit tests
  static void Test_StandardAllocDealloc();
  static void Test_CrossThreadAllocDealloc();    
  static void PerfTest_AllocDealloc();

private:
  ////// Global state across all threads ////////
  static ThreadSandboxNode* thread_memory_sandboxes;
  static std::mutex sandbox_list_mutex;
  static unsigned int base_arena_index;
  ////// Each thread will have its own global state here //////
  static thread_local unsigned int thread_id;
  static thread_local ThreadSandboxNode* thread_sandbox;
  static thread_local unsigned int mm_dealloc_error_status; /* nonzero means error */
  static thread_local unsigned int mm_alloc_error_status; /* nonzero means error */    
};

#endif