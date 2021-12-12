/*
MIT License

Copyright (c) 2021 Sterling Schulkins

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/
#ifndef MEMORY_MANAGER_H_INCLUDED
#define MEMORY_MANAGER_H_INCLUDED

// For quick disabling of memory management just comment this line
#define ENABLE_MEMORY_MANAGEMENT

#include <new>
#include <atomic>
#include <mutex>
#include <unordered_map>
#if _MSC_VER >= 1200
// visual studio specific compiler warnings
#pragma warning( push )
// visual studio will complain about mismatching annotations for new operator. not relevant for all C++ implementations
#pragma warning(disable : 28251)
#endif
// The Memory Manager handles preventing fragmentation of memory for systems with a lack of good virtual memory management.
// It globally overrides the new and delete c++ operators (but not malloc/free).
// It values performance speed over optimal space efficiency (some space will be wasted).
// It does this by allocating contiguous arenas of memory of geometrically 
// increasing sizes (doubling powers of two) based on allocation size.
// Based on my tests on an AMD Ryzen Threadripper machine running windows 10 64bit & visual studio 2019,
// it is about 3x slower than standard allocation, but 2x faster than standard deallocation.

// Terminology: 
// "Thread Sandbox" - A thread sandbox is simply the working space of memory that only one specific thread can touch. 
//    There can be as many thread sanboxes as there are number of threads in the application. 
//    We do this mostly so that each thread can avoid synchronization contention when accessing the memory that it allocates. 
//    Contention only arises when threads try to deallocate memory that was previously allocated on another thread. 
//    Therefore we have to track memory "ownership" per thread.
// "Arena" - A contiguous chunk of memory which contains individual cells of memory
// "Cell" - A single block of memory that is intended to be the smallest atomic unit for allocation managed by the memory manager. 
//          aka. the blocks used by outside code

#ifdef ENABLE_MEMORY_MANAGEMENT

// default new operator throws the std::bad_alloc exception upon failure
void* operator new(size_t size);
// to use this non-exception-throwing version of new you must explicitly call it, ie:
// Object* p = new (std::nothrow) Object();
void* operator new(size_t size, const std::nothrow_t&) noexcept;
// default new operator throws the std::bad_alloc exception upon failure
void* operator new[](size_t size);
// to use this non-exception-throwing version of new[] you must explicitly call it, ie:
// char* p = new (std::nothrow) char [1024];
void* operator new[](size_t size, const std::nothrow_t&) noexcept;

void operator delete(void* p);
void operator delete(void*, size_t size);
void operator delete(void*, size_t size, const std::nothrow_t&) noexcept;
void operator delete[](void*, size_t size);
void operator delete[](void* p, size_t size, const std::nothrow_t) noexcept;
void operator delete[](void* p);
#endif

class MemoryManager {
public:

  struct ArenaCollection;
  struct DeallocRequest;

  // A thread sandbox is simply the working memory space that only one specific thread can touch 
  struct ThreadSandboxNode {
    unsigned int thread_id;
    // the number of different sizes of arenas we have
    // this is essentially the length of the arenas array below
    unsigned int num_arena_sizes;
    // arenas is a 1-dimensional array of pointers where the first dimension represents arena size (powers of two doubling for every slot)
    // the contents of which is a pointer to an ArenaCollection which holds the head of a linked list of arenas. This array is fixed in size up to the maximum
    // number of arena sizes we support (controlled by MAX_CELL_SIZE). It is allocated at startup, and nullified. 
    // It is a sparse array, so only indices which have had allocations will have a non-null ArenaCollection pointer.
    ArenaCollection** arenas;
    ThreadSandboxNode* next;
    // other threads can request to make a deallocation on this thread
    // processing of this queue only happens when new allocations are made on this thread  
    std::mutex dealloc_mutex;
    std::atomic<unsigned int> num_deallocs_queued;
    std::atomic<unsigned int> deallocs_capacity;
    DeallocRequest* dealloc_queue; // this is a dynamic array of dealloc requests (can resize and grow larger if capacity runs out)
    // Derelict memory happens when the thread exits and cleanup begins but there are still occupied cells.
    // Derelict memory is bad because we can't confidently free it back to the OS because
    // it may still be in use by application code.
    // This can be caused by memory leaks (application bugs where there is an allocation without corresponding deallocation), 
    // but it can also be caused by static constructors/destructors that will race with the thread sandbox destructor.
    // Unfortunately static destructor order of execution is not reliable, so we just allow the memory to leak (dont free it). 
    // The process is exiting anyway in that case so it shouldn't be that big of a deal.
    // This is good motivation to avoid using static destructors in your code, but not the end of the world.
    // If it happens We mark the entire memory hierarchy as derelict, except for cells, 
    // to speed up checks for that case. (see ArenaCollection and ArenaHeader)
    bool derelict;
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
    // is this memory derelict? (see ThreadSandboxNode for definition of the term derelict memory)
    bool derelict;
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
    // is this memory derelict? (see ThreadSandboxNode for definition of the term derelict memory)
    bool derelict;
    // just occupies 8 bytes as a guard and as an integrity verification
    unsigned long long dummy_guard;    
  };

  // Header for a single block of memory that is intended to be the smallest atomic unit for allocation managed by the memory manager.
  //          aka. the blocks used by application code
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

  static void* Allocate(size_t size, void (*error_handler)());
  static void Deallocate(void* data, size_t size);

  static void HandleAllocErrorThrow();
  static void HandleAllocErrorNoThrow() noexcept;

  static void ClearAllocErrors();
  static void ClearDeallocErrors();

  static ThreadSandboxNode* AllocateNewThreadSandbox(ThreadSandboxNode* tail_of_list, unsigned int thread_id);
  static inline ThreadSandboxNode* FindSandboxForThread(unsigned int thread_id, ThreadSandboxNode*& last_node);
  // alignment_bytes is the byte address alignment we desire, for example 4 or 8, or 16
  static ArenaHeader* AllocateArenaOfMemory(size_t cell_size_without_header_bytes, size_t alignment_bytes, ArenaCollection* arena_collection);

  static inline unsigned int CalculateCellSizeAndArenaIndexForAllocation(size_t allocation_size, unsigned int& arena_index);
  static inline unsigned int CalculateCellCapacityForArena(unsigned int cell_size, unsigned int max_arena_size, unsigned int max_cells_per_arena);

  // deallocate all thread memory and shut down
  static void ThreadShutdown();

  //There is one additional wrinkle: Even though we keep thread memory sandboxes separate, one thread may try to delete memory in another thread sandbox.
  //In this case we need to put the delete request from the alien thread on a queue and then process it on the local thread at a later time.
  //Access to this queue MUST be synchronized with a mutex.
  // We operate with the observations:
  //a) often the object is freed by the same thread that had allocated it, and
  //b) when the object is deleted by a different thread, it does not interfere with all other threads, 
  //   but only with those that need to use the same pending requests list

  // Unit tests
  static void Test_StandardAllocDealloc();
  static void Test_CrossThreadAllocDealloc();
  static void Test_ErrorHandling();
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

#if _MSC_VER >= 1200
// visual studio specific compiler warnings
#pragma warning ( pop )
#endif

#endif
