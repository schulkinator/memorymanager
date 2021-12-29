#include "MemoryManager.h"

// If no logging function MEM_MGR_LOG is defined, define a default
#ifndef MEM_MGR_LOG
  #include <stdio.h>  
  #define MEM_MGR_LOG( str, ... ) printf(str, __VA_ARGS__)
#endif

#include <thread>
#include <algorithm>
#include <stdint.h>
#include <cassert>
#include <unordered_set>
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <heapapi.h>
#include <Processthreadsapi.h>
#include <intrin.h>
#elif
#include <unistd.h> // for sysconf
#endif

#if _MSC_VER >= 1200
// visual studio specific compiler warnings
// visual studio will complain about mismatching annotations for new operator. not relevant for all C++ implementations
#pragma warning(disable : 28251)
#endif

// Memory allocation values
#define MAX_CELL_SIZE 8388608 /* anything above this cell size is not put in an arena by the system */
#define MAX_ARENA_SIZE 8388608 /* we do not create arenas larger than this size (not including cell headers). the cell capacity of an arena will be reduced if needed so that it satisfies this restriction*/
#define MAX_CELLS_PER_ARENA 64 /* there can only be up to 64 cells in an arena. (but there can be less) */
#define OUTSIDE_SYSTEM_MARKER 0xBACBAA55
#define BYTE_ALIGNMENT 8 /* these days most 64bit CPUs prefer 8-byte alignment */
#define VALID_ARENA_HEADER_MARKER 0xAAAAFEED6DADB0D5
#define VALID_CELL_HEADER_MARKER 0xCE77BEEFFEEDDAD5

// Macro to count the number of zeroes after the least significant bit.
// For example the integer value 12 would return 2.
// TODO: these may not be supported by all compilers 
// Looks like there is a swift-specific function on apple platforms: https://developer.apple.com/documentation/swift/int/2886165-trailingzerobitcount
#if defined _M_X64 || defined _M_IX86 || defined __x86_64__
  #define COUNT_NUM_TRAILING_ZEROES_UINT32(bits) _tzcnt_u32(bits) /* This is an x86 specific BMI instruction intrinsic */
#else
  #define COUNT_NUM_TRAILING_ZEROES_UINT32(bits) __builtin_ctz(bits)
#endif

// Macro to count the leading number of zeros before the most significant bit.
#if defined _M_X64 || defined _M_IX86 || defined __x86_64__
  #define COUNT_NUM_LEADING_ZEROES_UINT32(bits) _lzcnt_u32(bits) /* This is an x86 specific BMI instruction intrinsic */
#else
  #define COUNT_NUM_LEADING_ZEROES_UINT32(bits) __builtin_clzl(bits)
#endif

#if defined _M_X64 || defined _M_IX86 || defined __x86_64__
#define COUNT_NUM_LEADING_ZEROES_UINT64(bits) _lzcnt_u64(bits) /* This is an x86 specific BMI instruction intrinsic */
#else
#define COUNT_NUM_LEADING_ZEROES_UINT64(bits) __builtin_clzll(bits)
// I've also seen this as _BitScanReverse64 in some places
#endif

// intrinsic based version for 64bit uint
#define NEXT_POW2_UINT64(n) \
n == 1 ? 1 : 1<<(64-COUNT_NUM_LEADING_ZEROES_UINT64(n-1))

// intrinsic based version for 32bit uint
#define NEXT_POW2_UINT32(n) \
n == 1 ? 1 : 1<<(32-COUNT_NUM_LEADING_ZEROES_UINT32(n-1))

#define RAND_IN_RANGE(min, max) rand() % ((max) - (min)) + 1 + min

// Threading macros
#ifdef _WIN32
#define GET_CURRENT_THREAD_ID() ::GetCurrentThreadId()
#elif __APPLE__  
  #if TARGET_IPHONE_SIMULATOR
  #define GET_CURRENT_THREAD_ID() static_cast<unsigned int>(pthread_mach_thread_np(pthread_self()))
  // iOS Simulator
  #elif TARGET_OS_IPHONE
  #define GET_CURRENT_THREAD_ID() static_cast<unsigned int>(pthread_mach_thread_np(pthread_self()))
  // iOS device
  #elif TARGET_OS_MAC
  #define GET_CURRENT_THREAD_ID() static_cast<unsigned int>(pthread_self())
  #else
  //#   error "Unknown Apple platform"
  #define GET_CURRENT_THREAD_ID() static_cast<unsigned int>(pthread_self())
  #endif
#elif __ANDROID__
#define GET_CURRENT_THREAD_ID() static_cast<unsigned int>(gettid())
#elif __linux__
#define GET_CURRENT_THREAD_ID() static_cast<unsigned int>(gettid())
#endif

// kernel-level allocation/free functions. These allow us to jump over a level of function call overhead with malloc() for performance
#ifdef _WIN32
HANDLE mm_proc_heap;
thread_local HANDLE mm_thread_heap; // the thread-local heap handle (unique to each thread)
SYSTEM_INFO mm_sys_info;
#define KMALLOC(size) static_cast<void*>(HeapAlloc(mm_thread_heap, HEAP_NO_SERIALIZE, (size))) /* NOTE: we allow HEAP_NO_SERIALIZE because each thread has its own heap, so no synchronization is necessary */
#define KREALLOC(ptr, size) static_cast<void*>(HeapReAlloc(mm_thread_heap, HEAP_NO_SERIALIZE | HEAP_REALLOC_IN_PLACE_ONLY, static_cast<LPVOID>(ptr), (size)))
#define KCALLOC(nitems, size) static_cast<void*>(HeapAlloc(mm_thread_heap, HEAP_NO_SERIALIZE | HEAP_ZERO_MEMORY, (nitems)*(size)))
#define KFREE(ptr) HeapFree(mm_thread_heap, HEAP_NO_SERIALIZE, (ptr)) /* NOTE: we allow HEAP_NO_SERIALIZE because each thread has its own heap, so no synchronization is necessary */
#define GLOBAL_KMALLOC(size) static_cast<void*>(HeapAlloc(mm_proc_heap, 0, (size))) /* since this is the process heap, we must force serialization */
#define GLOBAL_KREALLOC(ptr, size) static_cast<void*>(HeapReAlloc(mm_proc_heap, HEAP_REALLOC_IN_PLACE_ONLY, static_cast<LPVOID>(ptr), (size))) /* since this is the process heap, we must force serialization */
#define GLOBAL_KCALLOC(nitems, size) static_cast<void*>(HeapAlloc(mm_proc_heap, HEAP_ZERO_MEMORY, (nitems)*(size))) /* since this is the process heap, we must force serialization */
#define GLOBAL_KFREE(ptr) HeapFree(mm_proc_heap, 0, (ptr)) /* since this is the process heap, we must force serialization */
#define GET_SYS_PAGESIZE() (mm_sys_info.dwPageSize)
#elif __APPLE__
#elif __ANDROID__
#elif __linux__
#else
#define KMALLOC(size) malloc(size)
#define KREALLOC(ptr, size) realloc(ptr, size)
#define KFREE(ptr) free(ptr)
#define KCALLOC(nitems, size) calloc(nitems, size)
#define GLOBAL_KMALLOC(size) malloc(size)
#define GLOBAL_KREALLOC(ptr, size) realloc(ptr, size)
#define GLOBAL_KFREE(ptr) free(ptr)
#define GLOBAL_KCALLOC(nitems, size) calloc(nitems, size)
#define GET_SYS_PAGESIZE() sysconf(_SC_PAGE_SIZE)
#endif


#ifdef ENABLE_MEMORY_MANAGEMENT


// default std::bad_alloc exception throwing version
void* operator new(size_t size) {
  void* r = MemoryManager::Allocate(size, MemoryManager::HandleAllocErrorThrow);
  return r;
}

void* operator new(size_t size, const std::nothrow_t&) noexcept {
  void* r = MemoryManager::Allocate(size, MemoryManager::HandleAllocErrorNoThrow);
  return r;
}

// default std::bad_alloc exception throwing version
void* operator new[](size_t size) {
  void* r = MemoryManager::Allocate(size, MemoryManager::HandleAllocErrorThrow);
  return r;
}

void* operator new[](size_t size, const std::nothrow_t&) noexcept {
  void* r = MemoryManager::Allocate(size, MemoryManager::HandleAllocErrorNoThrow);
  return r;
}


void operator delete(void* data) {
  MemoryManager::Deallocate(data, 0);
}

void operator delete(void* data, size_t size) {
  MemoryManager::Deallocate(data, size);
}

void operator delete(void* data, size_t size, const std::nothrow_t&) noexcept {
  MemoryManager::Deallocate(data, size);
}

void operator delete[](void* data, size_t size) {
  MemoryManager::Deallocate(data, size);
}

void operator delete[](void* data, size_t size, const std::nothrow_t&) noexcept {
  MemoryManager::Deallocate(data, size);
}

void operator delete[](void* p) {
  MemoryManager::Deallocate(p, 0);
}
#endif

void MemoryManager::HandleAllocErrorThrow() {
  MemoryManager::thread_state.mm_alloc_error_status = 1;
  throw std::bad_alloc();
}

void MemoryManager::HandleAllocErrorNoThrow() noexcept {
  MemoryManager::thread_state.mm_alloc_error_status = 1;
}

void MemoryManager::ClearAllocErrors() {
  // clears alloc errors on this thread (each thread has its own error status)
  MemoryManager::thread_state.mm_alloc_error_status = 0;
}

void MemoryManager::ClearDeallocErrors() {
  // clears dealloc errors on this thread (each thread has its own error status)
  MemoryManager::thread_state.mm_dealloc_error_status = 0;
}

// global state constructor
MemoryManager::GlobalState::GlobalState() :
  base_arena_index(COUNT_NUM_TRAILING_ZEROES_UINT32(BYTE_ALIGNMENT)),
  thread_memory_sandboxes(nullptr),
  mm_global_error_status(0) {
#ifdef _WIN32
  GetSystemInfo(&mm_sys_info);
  mm_proc_heap = GetProcessHeap();
  if (mm_proc_heap == nullptr) {
    mm_global_error_status = 1;
    MEM_MGR_LOG("Memory manager error: could not get process heap handle");
  }
#endif
}
MemoryManager::GlobalState MemoryManager::global_state;

////// Each thread will have its own global state here //////
// thread constructor
MemoryManager::ThreadState::ThreadState() : 
  mm_dealloc_error_status(0), 
  mm_alloc_error_status(0), 
  thread_sandbox(nullptr),
  thread_id(0) {
#ifdef _WIN32
  // create a heap for this thread and don't use thread synchronization to protect allocations (we have our own thread protection mechanism)
  mm_thread_heap = HeapCreate(HEAP_NO_SERIALIZE, 0, 0);
#endif
}
// thread destructor
MemoryManager::ThreadState::~ThreadState() {
  MemoryManager::ThreadShutdown();
#ifdef _WIN32
  HeapDestroy(mm_thread_heap);
#endif
}
thread_local MemoryManager::ThreadState MemoryManager::thread_state;

void* MemoryManager::Allocate(size_t size, void (*error_handler)()) {
  if (size == 0) {
    return nullptr;
  }
  else if (size > MAX_CELL_SIZE) {
    // beyond MAX_ALLOCATION_SIZE we don't care, we're more concerned about small allocations fragmenting memory    
    // stamp down a header to mark it as outside memory
    unsigned char* p = reinterpret_cast<unsigned char*>(KMALLOC(size + BYTE_ALIGNMENT));
    if (!p) {
      // allocation failed
      error_handler();
      return nullptr;
    }
    unsigned int* u = reinterpret_cast<unsigned int*>(p);
    *u = OUTSIDE_SYSTEM_MARKER;
    // advance past the marker
    p += BYTE_ALIGNMENT;
    return reinterpret_cast<void*>(p);
  }
  // allocations below the byte alignment size make no sense either (including zero size allocations)
  // But that will be enforced in the below CalculateCellSizeAndArenaIndexForAllocation()
  if (!MemoryManager::thread_state.thread_id) {
    MemoryManager::thread_state.thread_id = GET_CURRENT_THREAD_ID(); // TODO: can this be in the static init instead of here?
  }
  // The first sandbox in existence (the head of the list) is a special case, create it if it doesn't exist
  if (!MemoryManager::global_state.thread_memory_sandboxes) {
    std::lock_guard<std::mutex> guard(MemoryManager::global_state.sandbox_list_mutex);
    // double check that the thread_memory_sandbox is still null since we could get two
    // simultaneous threads blocking on that mutex at the exact same time, the loser thread
    // would need to not run this code
    if (!MemoryManager::global_state.thread_memory_sandboxes) {
      MemoryManager::global_state.thread_memory_sandboxes = (ThreadSandboxNode*)AllocateNewThreadSandbox(nullptr, MemoryManager::thread_state.thread_id);
      if (!MemoryManager::global_state.thread_memory_sandboxes) {
        // thread sandbox allocation failed
        error_handler();
        return nullptr;
      }
      MemoryManager::thread_state.thread_sandbox = MemoryManager::global_state.thread_memory_sandboxes;
    }
  }
  ThreadSandboxNode* prev_sandbox = nullptr;
  if (!MemoryManager::thread_state.thread_sandbox) {
    // we need a mutex lock any time we walk the full sandbox list since other threads can alter it if they are shut down
    std::lock_guard<std::mutex> guard(MemoryManager::global_state.sandbox_list_mutex);
    MemoryManager::thread_state.thread_sandbox = FindSandboxForThread(MemoryManager::thread_state.thread_id, prev_sandbox);
  }
  if (!MemoryManager::thread_state.thread_sandbox) {
    // we did not find a sandbox for this thread, we must make one
    // only one thread at a time is allowed to make a new sandbox
    std::lock_guard<std::mutex> guard(MemoryManager::global_state.sandbox_list_mutex);
    MemoryManager::thread_state.thread_sandbox = AllocateNewThreadSandbox(prev_sandbox, MemoryManager::thread_state.thread_id);
    if (!MemoryManager::thread_state.thread_sandbox) {
      // thread sandbox allocation failed
      error_handler();
      return nullptr;
    }
  }
  // now we can process the sandbox
  // first, do we have any cross-thread dealloc requests to handle?
  ProcessDeallocationRequests(MemoryManager::thread_state.thread_sandbox);
  // which cell size do we need for this allocation? (doesn't make sense to allocate anything smaller than BYTE_ALIGNMENT number of bytes)
  unsigned int cell_size_without_header = 0;
  unsigned int arena_index = 0;
  cell_size_without_header = CalculateCellSizeAndArenaIndexForAllocation(size, arena_index);
  // now we can grab the arena collection
  ArenaCollection* arena_collection = MemoryManager::thread_state.thread_sandbox->arenas[arena_index];
  ArenaHeader* arena_header = nullptr;
  if (!arena_collection) {
    // no arena collection was allocated for this allocation size yet, allocate it now    
    // since we use calloc, everything will be zero initialized for us
    arena_collection = reinterpret_cast<ArenaCollection*>(KCALLOC(1, sizeof(ArenaCollection)));
    if (!arena_collection) {
      // arena collection allocation failed
      error_handler();
      return nullptr;
    }    
    arena_collection->cell_size_bytes = cell_size_without_header;
    arena_collection->sandbox = MemoryManager::thread_state.thread_sandbox;
    arena_collection->derelict = false;
    MemoryManager::thread_state.thread_sandbox->arenas[arena_index] = arena_collection;
    arena_header = AllocateArenaOfMemory(cell_size_without_header, BYTE_ALIGNMENT, arena_collection);
    if (!arena_header) {
      // the allocation failed
      error_handler();
      return nullptr;
    }
    arena_collection->first = arena_header;
  }
  arena_header = arena_collection->first;
  if (arena_collection->recent_dealloc_arena && arena_collection->recent_dealloc_arena->num_cells_occupied < arena_collection->recent_dealloc_arena->cell_capacity) {
    // a recent dealloc has freed up a cell on another arena, take a shortcut!
    arena_header = arena_collection->recent_dealloc_arena;
    // if we alloc on that arena and we reach the max occupation, then forget that this is a recent dealloc arena
    if ((arena_header->num_cells_occupied + 1) >= arena_header->cell_capacity) {
      arena_collection->recent_dealloc_arena = nullptr;
    }
  }
  // now we're ready to see if we can use this arena
  while (arena_header->num_cells_occupied >= arena_header->cell_capacity) {
    // arena is full, use the next arena
    if (!arena_header->next) {
      // there's no next arena, allocate a new one
      arena_header->next = AllocateArenaOfMemory(cell_size_without_header, BYTE_ALIGNMENT, arena_collection);
      if (!arena_header->next) {
        // the allocation failed
        error_handler();
        return nullptr;
      }
    }
    arena_header = arena_header->next;
  }
  // track this arena as having a recent cell allocation
  arena_collection->recent_alloc_arena = arena_header;
  // we've found an arena with unoccupied cells, find a cell to occupy and mark it
  // TODO: there's got to be a clever bit-manipulation way to do this
  unsigned long long cell_occupation_bits = arena_header->cell_occupation_bits;
  unsigned int cell_index = 0;
  while ((cell_occupation_bits & 1ULL) == 1) {
    cell_occupation_bits = cell_occupation_bits >> 1;
    cell_index++;
  }
  // found it, mark it as occupied
  arena_header->num_cells_occupied++;
  arena_header->cell_occupation_bits = arena_header->cell_occupation_bits | (1ULL << cell_index);
  CellHeader* cell_header = reinterpret_cast<CellHeader*>(arena_header->arena_start + (cell_index * (sizeof(CellHeader) + arena_header->cell_size_bytes)));
  // the pointer we return is at the appropriate cell, past the header of the cell
  unsigned char* ptr = arena_header->arena_start + (cell_index * (sizeof(CellHeader) + arena_header->cell_size_bytes)) + sizeof(CellHeader);
  return reinterpret_cast<void*>(ptr);
}

int MemoryManager::ProcessDeallocationRequests(ThreadSandboxNode* owning_sandbox) {
  // TODO: this atomic access seems to be a performance bottleneck. Need to figure out a way to check it less often?
  while (owning_sandbox->num_deallocs_queued > 0) {
    std::lock_guard<std::mutex> guard(owning_sandbox->dealloc_mutex);
    owning_sandbox->num_deallocs_queued--;
    DeallocRequest* request = owning_sandbox->dealloc_queue + owning_sandbox->num_deallocs_queued;
    // TODO: should we release the lock here first before deallocating?
    Deallocate(request->data, request->size);
  }
  return 0;
}

inline unsigned int MemoryManager::CalculateCellSizeAndArenaIndexForAllocation(size_t allocation_size, unsigned int& arena_index) {
  if (allocation_size < BYTE_ALIGNMENT) {
    allocation_size = BYTE_ALIGNMENT;
  }
  uint32_t alloc_npow2 = static_cast<uint32_t>(allocation_size);
  alloc_npow2 = NEXT_POW2_UINT32(alloc_npow2);
  uint32_t cell_size_without_header = alloc_npow2;
    
  //arena_index = log(cell_size_without_header) / log(2.0f);
  //// ignore the first couple powers of two until we reach BYTE_ALIGNMENT size cells (that's where our cell sizes start)
  //unsigned int ignore_first_n = (log(BYTE_ALIGNMENT) / log(2.0f));
  //arena_index = arena_index - (ignore_first_n);
    
  // if we're guaranteed that cell_size_without_header is a power of two, 
  // then we can use a shortcut to calculate the arena index by counting the number of trailing zeroes in the cell size
  arena_index = COUNT_NUM_TRAILING_ZEROES_UINT32(cell_size_without_header);
  arena_index = arena_index - MemoryManager::global_state.base_arena_index;
  return cell_size_without_header;
}

inline unsigned int MemoryManager::CalculateCellCapacityForArena(unsigned int cell_size, unsigned int max_arena_size, unsigned int max_cells_per_arena) {
  return std::min(std::max(max_arena_size / cell_size, 1u), max_cells_per_arena);
}

MemoryManager::ThreadSandboxNode* MemoryManager::FindSandboxForThread(unsigned int thread_id, ThreadSandboxNode*& last_node) {
  ThreadSandboxNode* sandbox = MemoryManager::global_state.thread_memory_sandboxes;
  // walk the linked list to find the memory sandbox for this thread
  while (sandbox) {
    if (sandbox->thread_id == thread_id) {
      // this is our sandbox
      return sandbox;
    }
    last_node = sandbox;
    sandbox = sandbox->next;
  }
  return sandbox;
}

void MemoryManager::Deallocate(void* data, size_t size) {
  // TODO: for the converse case where we're doing a dealloc, could also have another pointer to the last alloc'ed arena header to speed up scanning
  // maybe a size of zero triggers a scan to figure out way to read the arena header from the data pointer? stamp down a pointer to the header in every cell?
  if (data == nullptr) {
    return;
  }
  // first, identify if this is an outside system allocation
  // it should be safe to read into the memory behind the given pointer because in any scenario you're
  // going to either read into a previous cell's memory, or you'll read into the arena header's dummy guard (that's why it's there)
  unsigned char* behind_ptr = reinterpret_cast<unsigned char*>(data) - BYTE_ALIGNMENT;
  unsigned int* marker_ptr = reinterpret_cast<unsigned int*>(behind_ptr);
  if (size > MAX_CELL_SIZE || (*marker_ptr == OUTSIDE_SYSTEM_MARKER)) {
    // beyond MAX_ALLOCATION_SIZE we don't care, we're more concerned about small allocations fragmenting memory     
    KFREE(behind_ptr);
    return;
  }
  // next we need to identify which sandbox this memory belongs to and if this is a cross-thread deallocation
  if (!MemoryManager::thread_state.thread_id) {
    MemoryManager::thread_state.thread_id = GET_CURRENT_THREAD_ID();
  }
  ThreadSandboxNode* prev_sandbox = nullptr;
  if (!MemoryManager::thread_state.thread_sandbox) {
    // we need a mutex lock any time we walk the full sandbox list since other threads can alter it if they are shut down
    std::lock_guard<std::mutex> guard(MemoryManager::global_state.sandbox_list_mutex);
    MemoryManager::thread_state.thread_sandbox = FindSandboxForThread(MemoryManager::thread_state.thread_id, prev_sandbox);
  }
  if (!MemoryManager::thread_state.thread_sandbox) {
    // we did not find a sandbox for this thread, we must make one
    // only one thread at a time is allowed to make a new sandbox
    std::lock_guard<std::mutex> guard(MemoryManager::global_state.sandbox_list_mutex);
    MemoryManager::thread_state.thread_sandbox = AllocateNewThreadSandbox(prev_sandbox, MemoryManager::thread_state.thread_id);
  }
  if (!MemoryManager::thread_state.thread_sandbox) {
    // we didn't find the sandbox for this thread. Something really bad must've happened!    
    MemoryManager::thread_state.mm_dealloc_error_status |= 1;
    return;
  }
  // we can look up the arena directly here by looking in the cell header
  // inside the cell header is a pointer to the arena header
  // are we authorized to deallocate on this thread?
  unsigned char* data_char = reinterpret_cast<unsigned char*>(data);
  CellHeader* cell_header = reinterpret_cast<CellHeader*>(data_char - sizeof(CellHeader));
  ArenaHeader* arena_header = nullptr;
  if (cell_header->dummy_guard == VALID_CELL_HEADER_MARKER) {
    // we have a valid cell header!    
    arena_header = cell_header->arena_header;
  }
  if (!arena_header || arena_header->dummy_guard != VALID_ARENA_HEADER_MARKER) {
    MemoryManager::thread_state.mm_dealloc_error_status |= 2;
    return;
  }
  // we have a valid arena header!
  // to verify if we have ownership of the memory on this thread, we need to go look up the sandbox for the alloc and make sure the thread ids match
  ArenaCollection* arena_collection = arena_header->arena_collection;
  ThreadSandboxNode* owning_sandbox = arena_collection->sandbox;
  if (!owning_sandbox) {
    MemoryManager::thread_state.mm_dealloc_error_status |= 4;
    return;
  }
  bool thread_safe = owning_sandbox->thread_id == MemoryManager::thread_state.thread_id;
  if (!thread_safe) {
    // we don't own this memory, so we can't deallocate it here. make a dealloc request on the owning sandbox
    int dealloc_status = MakeDeallocRequestOnOtherThread(owning_sandbox, data, size);
    if (dealloc_status) {
      MemoryManager::thread_state.mm_dealloc_error_status |= 8;
      return;
    }
    return;
  }
  // okay we for sure have ownership over this memory, mark it as deallocated
  arena_collection->recent_dealloc_arena = arena_header;
  arena_header->num_cells_occupied--;
  unsigned int cell_size_with_header = (sizeof(CellHeader) + arena_header->cell_size_bytes);
  // ok we found the arena it's in. turn off the bit in the arena header to mark it as unoccupied
  unsigned char* cell_start = reinterpret_cast<unsigned char*>(data) - sizeof(CellHeader);
  unsigned int bit_position_for_cell = static_cast<unsigned int>((cell_start - arena_header->arena_start) / cell_size_with_header);
  unsigned long long bit = ~(1ULL << bit_position_for_cell);
  arena_header->cell_occupation_bits = arena_header->cell_occupation_bits & bit;
}

int MemoryManager::MakeDeallocRequestOnOtherThread(ThreadSandboxNode* owning_sandbox, void* data, size_t size) {
  // we don't own this memory, so we can't deallocate it on this thread. make a dealloc request on the owning sandbox
  std::lock_guard<std::mutex> guard(owning_sandbox->dealloc_mutex);
  // if we don't have enough room to make a request, realloc more room (this includes the initial queue alloc)
  if (owning_sandbox->num_deallocs_queued == owning_sandbox->deallocs_capacity) {
    // minimum of 8 request slots
    unsigned int new_capacity = std::max(8u, owning_sandbox->deallocs_capacity * 2);
    DeallocRequest* new_queue = nullptr;
    if (owning_sandbox->dealloc_queue) {
      // this can be a slight source of fragmentation, since it can free the old memory and move it somewhere else. doesn't seem common enough to be of concern though
      // We have to use the global heap here because otherwise we're allocating memory from an alien thread's heap and then when we shut down the deallocating thread tries to free memory that isn't in its own heap
      new_queue = reinterpret_cast<DeallocRequest*>(GLOBAL_KREALLOC(owning_sandbox->dealloc_queue, sizeof(DeallocRequest) * (new_capacity)));
    }
    else {
      // very first queue alloc
      // since we use calloc, everything will be zero initialized for us
      // We have to use the global heap here because otherwise we're allocating memory from an alien thread's heap and then when we shut down the deallocating thread tries to free memory that isn't in its own heap
      new_queue = reinterpret_cast<DeallocRequest*>(GLOBAL_KCALLOC(new_capacity, sizeof(DeallocRequest)));
    }
    if (!new_queue) {
      return 1;
    }
    owning_sandbox->dealloc_queue = new_queue;
    owning_sandbox->deallocs_capacity = new_capacity;
  }
  // set the request
  DeallocRequest* request = owning_sandbox->dealloc_queue + owning_sandbox->num_deallocs_queued;
  request->data = data;
  request->size = size;
  owning_sandbox->num_deallocs_queued++;
  return 0;
}

MemoryManager::ThreadSandboxNode* MemoryManager::AllocateNewThreadSandbox(ThreadSandboxNode* tail_of_list, unsigned int thread_id) {
  // since we use calloc, everything will be zero initialized for us
  ThreadSandboxNode* thread_sandbox = reinterpret_cast<ThreadSandboxNode*>(KCALLOC(1, sizeof(ThreadSandboxNode)));
  if (!thread_sandbox) {
    // allocation failed
    return nullptr;
  }
  if (tail_of_list) {
    tail_of_list->next = thread_sandbox;
  }
  // allocate the arena index dimension
  // first calculate how many arenas we need based on arenas that have power-of-two size cells in them, doubling each time until we hit the max cell size
  // this will include an arena with 1-byte cells which isn't very useful, so we subtract off the first couple
  unsigned int arenas_needed = static_cast<unsigned int>(log(MAX_CELL_SIZE) / log(2.0f));
  // it will screw up byte alignment if we allow arenas that have cell sizes < BYTE_ALIGNMENT
  // so we need to ignore the first couple powers of two below a cell size of BYTE_ALIGNMENT
  unsigned int ignore_first_n = static_cast<unsigned int>(((log(BYTE_ALIGNMENT) / log(2.0f)) - 1));
  arenas_needed -= ignore_first_n;
  // now we know how many arenas we need, allocate the array of pointers to their collections
  // since we use calloc, everything will be zero initialized for us
  thread_sandbox->arenas = reinterpret_cast<ArenaCollection**>(KCALLOC(arenas_needed, sizeof(ArenaCollection*)));
  thread_sandbox->num_arena_sizes = arenas_needed;
  thread_sandbox->thread_id = thread_id;
  thread_sandbox->derelict = false;
  // because we malloc the thread sanbox we need to manually call the constructors of our member objects by doing a placement new
  new (&thread_sandbox->dealloc_mutex) (std::mutex);
  new (&thread_sandbox->num_deallocs_queued) (std::atomic<unsigned int>);
  new (&thread_sandbox->deallocs_capacity) (std::atomic<unsigned int>);
  return thread_sandbox;
}

MemoryManager::ArenaHeader* MemoryManager::AllocateArenaOfMemory(size_t cell_size_without_header_bytes, size_t alignment_bytes, ArenaCollection* arena_collection) {
  const size_t header_size = sizeof(ArenaHeader);
  // how many cells go in this arena?
  unsigned int cell_capacity = CalculateCellCapacityForArena(static_cast<unsigned int>(cell_size_without_header_bytes), MAX_ARENA_SIZE, MAX_CELLS_PER_ARENA);
  // The arena header is part of the contiguous block of memory along with the cells. The header is always part of the first bytes of memory.
  // the alignment_bytes bytes here allow us to make sure we have room for byte alignment padding between the header and the data cells *wherever* the OS decides to give us memory
  // each cell contains: a pointer to the arena header, some guard padding, then the cell data itself
  size_t arena_size = header_size + alignment_bytes + ((sizeof(CellHeader) + cell_size_without_header_bytes) * cell_capacity);
  unsigned char* raw_arena = reinterpret_cast<unsigned char*>(KMALLOC(arena_size));
  if (!raw_arena) {
    return nullptr;
  }
#if _MSC_VER >= 1200
  // visual studio will complain about a buffer overrun with the memset but that's not possible. arena_size can never be less than header_size.
#pragma warning( push )
#pragma warning(disable : 6386)
#endif
  // zero out only the header
  memset(raw_arena, 0, header_size);
#if _MSC_VER >= 1200
#pragma warning( pop )
#endif
  ArenaHeader* arena_header = reinterpret_cast<ArenaHeader*>(raw_arena);
  arena_header->cell_size_bytes = static_cast<unsigned int>(cell_size_without_header_bytes);
  arena_header->cell_capacity = cell_capacity;
  // this works based on the property that a power of two alignment number like 8 for example (1000 in binary)
  // will be 0111 once we subtract 1, giving us our mask.
  uint64_t padding_addr_mask = static_cast<unsigned int>(alignment_bytes - 1U);
  // figure out how many bytes past the header we can start the arena in order to be byte-aligned
  unsigned char* raw_arena_past_header = raw_arena + header_size;
  // any bits of the address that land within the mask area will signal that raw_arena_past_header is not on an address that is a multiple of alignment_bytes
  // and in fact tells us how many bytes past that multiple it is. Said another way, if raw_arena_past_header is at an address that is
  // a multiple of alignment_bytes, then all of the bits to the right of the most significant bit in alignment_bytes for the raw_arena_past_header address should be zero
  uint64_t masked_addr_past_header = (padding_addr_mask & reinterpret_cast<uint64_t>(raw_arena_past_header));
  // so for example, if masked_addr_past_header indicates we're 1 byte past a desired alignment, we need to move forward (alignment_bytes - 1) to land on an alignment boundary
  arena_header->arena_collection = arena_collection;
  arena_header->padding_size_bytes = static_cast<unsigned int>((alignment_bytes - masked_addr_past_header) % alignment_bytes);
  arena_header->arena_start = raw_arena + header_size + arena_header->padding_size_bytes;
  arena_header->arena_end = arena_header->arena_start + ((sizeof(CellHeader) + cell_size_without_header_bytes) * cell_capacity) - 1;
  arena_header->derelict = false;
  arena_header->dummy_guard = VALID_ARENA_HEADER_MARKER;
  // stamp down pointers to the arena header in every cell header so that deallocation is speedy
  for (uint_fast16_t i = 0; i < cell_capacity; ++i) {
    unsigned char* cell_header_raw = (arena_header->arena_start + ((sizeof(CellHeader) + cell_size_without_header_bytes) * i));
    CellHeader* cell_header = reinterpret_cast<CellHeader*>(cell_header_raw);
    cell_header->arena_header = arena_header;
    cell_header->dummy_guard = VALID_CELL_HEADER_MARKER;
  }
  arena_collection->num_arenas++;
  return arena_header;
}

void MemoryManager::ThreadShutdown() {
  // this shutdown runs per-thread. (Each thread shuts down for itself.)
  // TODO: currently, we just have each thread free its own arena memory. 
  //     but if we have a lot of threads coming and going, this actually causes fragmentation of its own 
  //     (because it blasted a big hole in the contiguous heap memory where this thread had memory allocated)
  //     So to fix this, we need an exiting thread to transfer ownership of its memory to another active thread, 
  //     and then only the last thread exiting does the actual free()
  if (!MemoryManager::thread_state.thread_sandbox) {
    // we're going to walk the sandbox linked list, so lock the mutex  
    std::lock_guard<std::mutex> guard(MemoryManager::global_state.sandbox_list_mutex);
    ThreadSandboxNode* prev_sandbox = nullptr;
    MemoryManager::thread_state.thread_sandbox = FindSandboxForThread(MemoryManager::thread_state.thread_id, prev_sandbox);
  }
  if (!MemoryManager::thread_state.thread_sandbox) {
    return;
  }
  // process queued deallocs from other threads if there are any waiting
  ProcessDeallocationRequests(MemoryManager::thread_state.thread_sandbox);
  // kill all the arenas for this thread
  for (uint32_t i = 0; i < MemoryManager::thread_state.thread_sandbox->num_arena_sizes; ++i) {
    ArenaCollection* arena_collection = MemoryManager::thread_state.thread_sandbox->arenas[i];
    // its totally valid (and intentional) for arena collections to be left null, so avoid that
    if (!arena_collection) {
      continue;
    }
    ArenaHeader* arena_header = arena_collection->first;
    arena_collection->first = nullptr; // null this out first so we can check if we have wired up a derelict
    ArenaHeader* arena_header_curr_derelict = nullptr; // keep track of the most recent derelict encountered
    while (arena_header) {
      if (arena_header->num_cells_occupied == 0) {
        // destroy that arena
        ArenaHeader* next_arena_header = arena_header->next;
        KFREE(arena_header);
        arena_header = next_arena_header;        
      } else {
        // DERELICT!
        // uh oh, we have encountered some derelict memory. 
        // Someone didn't deallocate before the thread exited (usually caused by static destructors)
        // now we need to mark the hierarchy as derelict and keep this link intact.
        MEM_MGR_LOG("Encountered derelict memory on thread %d", MemoryManager::thread_state.thread_id);
        if (!arena_collection->first) {
          // wire it up as the new head of the linked list if none present
          arena_collection->first = arena_header;
        }
        if (arena_header_curr_derelict) {
          // wire the derelicts to link together
          arena_header_curr_derelict->next = arena_header;
        }
        arena_header_curr_derelict = arena_header;
        arena_header->derelict = true;
        arena_collection->derelict = true;
        MemoryManager::thread_state.thread_sandbox->derelict = true;
        arena_header = arena_header->next;
      }      
    }
    // make sure the terminating arena in a derelict scenario has a null next pointer
    if (arena_header_curr_derelict) {
      arena_header_curr_derelict->next = nullptr;
    }
    if (!arena_collection->derelict) {
      KFREE(arena_collection);
      MemoryManager::thread_state.thread_sandbox->arenas[i] = nullptr;
    }    
  }
  // at this point if this is derelict thread memory then we don't proceed with the rest of the teardown for this thread
  if (MemoryManager::thread_state.thread_sandbox->derelict) {
    return;
  }
  {
    // deallocate the dealloc_queue for this thread
    // we need to mess with the queue for this sandbox, so lock the dealloc queue mutex
    std::lock_guard<std::mutex> guard(MemoryManager::thread_state.thread_sandbox->dealloc_mutex);
    // the dealloc queue is allocated on the global process heap, so must use the corresponding free for that
    GLOBAL_KFREE(MemoryManager::thread_state.thread_sandbox->dealloc_queue);
    MemoryManager::thread_state.thread_sandbox->dealloc_queue = nullptr;
    MemoryManager::thread_state.thread_sandbox->num_deallocs_queued = 0;
    MemoryManager::thread_state.thread_sandbox->deallocs_capacity = 0;
  }
  {
    // we're going to need to mess with the sandbox linked list, so lock the mutex  
    std::lock_guard<std::mutex> guard(MemoryManager::global_state.sandbox_list_mutex);
    // Threads can come in and out of existence all the time, if our
    //  thread exit behavior is that we kill one of the sandboxes in the sandbox linked list
    //  then we'll create a broken linked list for the rest of the system. Not good! 
    // So we need to wire up the next pointer of the previous sandbox to skip over this dead thread sandbox.
    ThreadSandboxNode* prev_node = nullptr;
    ThreadSandboxNode* curr_node = MemoryManager::global_state.thread_memory_sandboxes;
    while (curr_node && curr_node->thread_id != MemoryManager::thread_state.thread_sandbox->thread_id) {
      prev_node = curr_node;
      curr_node = curr_node->next;
    }
    if (prev_node && curr_node) {
      prev_node->next = curr_node->next;
    }
    if (curr_node && curr_node == MemoryManager::global_state.thread_memory_sandboxes) {
      // it was the head of the linked list, so fix that
      MemoryManager::global_state.thread_memory_sandboxes = curr_node->next;
    }
  }
  KFREE(MemoryManager::thread_state.thread_sandbox);
  MemoryManager::thread_state.thread_sandbox = nullptr;
  // TODO: we need to change this so that the last thread to exit destroys the main linked list of sandboxes
  // this should be safe as long as each thread already has its own thread-local sandbox cached
  //std::lock_guard<std::mutex> guard(sandbox_list_mutex);
  //if (thread_memory_sandboxes != nullptr) {    
  //  KFREE(thread_memory_sandboxes);
  //  thread_memory_sandboxes = nullptr;
  //}
}

void MemoryManager::Test_StandardAllocDealloc() {
  assert(MemoryManager::global_state.base_arena_index == COUNT_NUM_TRAILING_ZEROES_UINT32(BYTE_ALIGNMENT));
  // 8 byte object
  struct MMTestStructTiny {
    uint64_t thing1;
  };
  // 800 byte object
  struct MMTestStructMedium {
    uint64_t thing1[100];
  };
  // 8MB object
  struct MMTestStructBig {
    uint64_t thing1[1000000];
  };
    
  // first find our thread sandbox
  ThreadSandboxNode* prev_sandbox = nullptr;
  if (!MemoryManager::thread_state.thread_id) {
    MemoryManager::thread_state.thread_id = GET_CURRENT_THREAD_ID();
  }
  MemoryManager::ClearAllocErrors();
  MemoryManager::ClearDeallocErrors();
    
  // make an alloc
  MMTestStructTiny* a = new MMTestStructTiny;

  ThreadSandboxNode* sandbox = MemoryManager::global_state.thread_memory_sandboxes;
  sandbox = FindSandboxForThread(MemoryManager::thread_state.thread_id, prev_sandbox);
  // the sandbox we searched for manually should match the sandbox for this thread in the thread state
  assert(sandbox == MemoryManager::thread_state.thread_sandbox); // "thread-local thread_sandbox does not match?"

  // validate global state
  ArenaCollection* collection = sandbox->arenas[0];
  assert(collection != nullptr);    
  assert(collection->num_arenas == 1);
  assert(collection->cell_size_bytes == BYTE_ALIGNMENT);
  assert(collection->recent_alloc_arena == collection->first);
  ArenaHeader* arena_header = collection->first;
  assert(arena_header->cell_size_bytes == BYTE_ALIGNMENT);
  assert(arena_header->arena_collection == collection);
  assert(arena_header->num_cells_occupied == 1);
  assert(arena_header->next == nullptr);
  assert(arena_header->dummy_guard == VALID_ARENA_HEADER_MARKER);    
  assert(MemoryManager::thread_state.mm_alloc_error_status == 0);

  // make another alloc
  MMTestStructMedium* b = new MMTestStructMedium;
  // since this is 800 bytes it should end up in the 1024 arena, which is the 8th index
  collection = sandbox->arenas[7];
  assert(collection != nullptr);
  assert(collection->num_arenas == 1);
  assert(collection->cell_size_bytes == 1024);
  assert(collection->recent_alloc_arena == collection->first);
  arena_header = collection->first;
  assert(arena_header->cell_size_bytes == 1024);
  assert(arena_header->arena_collection == collection);
  assert(arena_header->num_cells_occupied == 1);
  assert(arena_header->next == nullptr);
  assert(arena_header->dummy_guard == VALID_ARENA_HEADER_MARKER);
  assert(MemoryManager::thread_state.mm_alloc_error_status == 0);

  // make a dealloc
  delete b;
  // since this is 800 bytes it should end up in the 1024 arena, which is the 8th index
  collection = sandbox->arenas[7];
  assert(collection != nullptr);
  assert(collection->num_arenas == 1);
  assert(collection->cell_size_bytes == 1024);
  assert(collection->recent_dealloc_arena == collection->first);
  arena_header = collection->first;
  assert(arena_header->cell_size_bytes == 1024);
  assert(arena_header->arena_collection == collection);
  assert(arena_header->num_cells_occupied == 0);
  assert(arena_header->next == nullptr);
  assert(arena_header->dummy_guard == VALID_ARENA_HEADER_MARKER);
  assert(MemoryManager::thread_state.mm_dealloc_error_status == 0);

  // make a big alloc
  MMTestStructBig* c = new MMTestStructBig;
  // since this is 8MB it should end up in the 8MB arena (the biggest), which is the 21st index
  collection = sandbox->arenas[20];
  assert(collection != nullptr);
  assert(collection->num_arenas == 1);
  assert(collection->cell_size_bytes == MAX_CELL_SIZE);
  assert(collection->recent_alloc_arena == collection->first);
  arena_header = collection->first;
  assert(arena_header->cell_size_bytes == MAX_CELL_SIZE);
  assert(arena_header->arena_collection == collection);
  assert(arena_header->num_cells_occupied == 1);
  assert(arena_header->next == nullptr);
  assert(arena_header->dummy_guard == VALID_ARENA_HEADER_MARKER);
  assert(MemoryManager::thread_state.mm_alloc_error_status == 0);
  delete a;
  delete c;
}

void MemoryManager::Test_StochasticAllocDealloc() {
  // for this test we want to pseudo-randomly allocate a mass amount of different sizes and validate them
  MemoryManager::ClearAllocErrors();
  MemoryManager::ClearDeallocErrors();
  const int num_allocs = 10000;
  // have to use calloc so that we avoid using the memory manager for this test code
  unsigned char** alloc_list = static_cast<unsigned char**>(KCALLOC(num_allocs, sizeof(unsigned char*)));
  unsigned int* size_list = static_cast<unsigned int*>(KCALLOC(num_allocs, sizeof(unsigned int)));
  assert(alloc_list != nullptr);
  if (alloc_list == nullptr) {
    return;
  }
  assert(size_list != nullptr);
  if (size_list == nullptr) {
    return;
  }
  // allocate and hold on to the memory
  for (int i = 0; i < num_allocs; ++i) {    
    uint32_t alloc_size = RAND_IN_RANGE(1, MAX_CELL_SIZE);
    size_list[i] = alloc_size;
    alloc_list[i] = new unsigned char[alloc_size];
    // basic assertions
    assert(alloc_list[i] != nullptr);
    uint32_t arena_index = 0;
    uint32_t cell_size_without_header = CalculateCellSizeAndArenaIndexForAllocation(alloc_size, arena_index);
    ArenaCollection* arena_collection = MemoryManager::thread_state.thread_sandbox->arenas[arena_index];
    unsigned char* data_char = reinterpret_cast<unsigned char*>(alloc_list[i]);
    // get the arena header from the cell header
    CellHeader* cell_header = reinterpret_cast<CellHeader*>(data_char - sizeof(CellHeader));
    assert(cell_header->dummy_guard == VALID_CELL_HEADER_MARKER);
    ArenaHeader* arena = cell_header->arena_header;
    // arena collection is valid
    assert(arena_collection != nullptr);
    // the arena collection has the expected arena as its recent alloc
    assert(arena_collection->recent_alloc_arena == arena);
    // its the cell size we expect
    assert(cell_size_without_header == arena->cell_size_bytes);
    // randomly deallocate stuff to simulate fragmentation over time
    if ((RAND_IN_RANGE(0, 100)) < 30) {
      // pick a random allocation to deallocate
      int j = RAND_IN_RANGE(0, i);
      if (alloc_list[j] == nullptr) {
        continue;
      }
      // before we deallocate, grab the arena for that allocation so we can watch it change before and after the deallocation
      uint32_t arena_index = 0;
      uint32_t cell_size_without_header = CalculateCellSizeAndArenaIndexForAllocation(size_list[j], arena_index);
      ArenaCollection* arena_collection = MemoryManager::thread_state.thread_sandbox->arenas[arena_index];
      unsigned char* data_char = reinterpret_cast<unsigned char*>(alloc_list[j]);
      // get the arena header from the cell header
      CellHeader* cell_header = reinterpret_cast<CellHeader*>(data_char - sizeof(CellHeader));
      assert(cell_header->dummy_guard == VALID_CELL_HEADER_MARKER);
      ArenaHeader* arena = cell_header->arena_header;
      auto num_cells_occupied_before = arena->num_cells_occupied;
      auto cell_occupation_bits_before = arena->cell_occupation_bits;
      // arena collection is valid
      assert(arena_collection != nullptr);
      // do the deallocation
      delete alloc_list[j];
      // the arena collection has the expected arena as its recent dealloc
      assert(arena_collection->recent_dealloc_arena == arena);
      // the number of occupied cells went down by one
      assert(arena->num_cells_occupied == (num_cells_occupied_before - 1));
      // cell occupation bits changed
      assert(arena->cell_occupation_bits != cell_occupation_bits_before);
      // null out that element so we dont try to dealloc it again
      alloc_list[j] = nullptr;
    }
  }  
  // deallocate everything
  for (int i = 0; i < num_allocs; ++i) {
    if (alloc_list[i] == nullptr) {
      continue;
    }
    // before we deallocate, grab the arena for that allocation so we can watch it change before and after the deallocation
    uint32_t arena_index = 0;
    uint32_t cell_size_without_header = CalculateCellSizeAndArenaIndexForAllocation(size_list[i], arena_index);
    ArenaCollection* arena_collection = MemoryManager::thread_state.thread_sandbox->arenas[arena_index];
    unsigned char* data_char = reinterpret_cast<unsigned char*>(alloc_list[i]);
    // get the arena header from the cell header
    CellHeader* cell_header = reinterpret_cast<CellHeader*>(data_char - sizeof(CellHeader));
    assert(cell_header->dummy_guard == VALID_CELL_HEADER_MARKER);
    ArenaHeader* arena = cell_header->arena_header;
    auto num_cells_occupied_before = arena->num_cells_occupied;
    auto cell_occupation_bits_before = arena->cell_occupation_bits;
    // arena collection is valid
    assert(arena_collection != nullptr);
    // do the deallocation
    delete alloc_list[i];
    // the arena collection has the expected arena as its recent dealloc
    assert(arena_collection->recent_dealloc_arena == arena);
    // the number of occupied cells went down by one
    assert(arena->num_cells_occupied == (num_cells_occupied_before - 1));
    // cell occupation bits changed
    assert(arena->cell_occupation_bits != cell_occupation_bits_before);
  }
  KFREE(alloc_list);
  KFREE(size_list);
}

void MemoryManager::Test_CrossThreadAllocDealloc() {
  struct MMTestStructTiny {
    uint64_t thing1;
  };
  // make allocs on different threads and dealloc across threads
  MMTestStructTiny* a = new MMTestStructTiny;
  std::atomic<bool> t1_done = false;
  std::thread t1([&a, &t1_done]() {
    delete a;
    t1_done = true;
    });
  // block and wait until t1 finishes (but don't let the thread exit yet, since that would trigger the thread shutdown code)
  while (!t1_done.load()) {
  }
  // do an alloc back on the main thread to trigger the dealloc
  a = new MMTestStructTiny;
  // now verify everything looks correct
  ThreadSandboxNode* sandbox = nullptr;
  {
    // NOTE: any time we walk the sandbox list we have to lock this mutex
    std::lock_guard<std::mutex> guard(MemoryManager::global_state.sandbox_list_mutex);
    sandbox = MemoryManager::global_state.thread_memory_sandboxes;
    int count_sandboxes = 0;
    while (sandbox) {
      count_sandboxes++;
      ArenaCollection* collection = sandbox->arenas[0];
      if (count_sandboxes == 1) {
        // on the first thread, we've made an allocation, so it should have an arena collection present
        assert(collection != nullptr);
        assert(collection->num_arenas == 1);
        assert(collection->cell_size_bytes == sizeof(MMTestStructTiny)); // NOTE: this should be a power of two
        assert(collection->recent_alloc_arena == collection->first);
        ArenaHeader* arena_header = collection->first;
        assert(arena_header->cell_size_bytes == sizeof(MMTestStructTiny)); // NOTE: this should be a power of two
        assert(arena_header->arena_collection == collection);
        assert(arena_header->num_cells_occupied == 1); // we alloced, then deleted, then alloced. so should just be one cell occupied
        assert(arena_header->next == nullptr);
        assert(arena_header->dummy_guard == VALID_ARENA_HEADER_MARKER);
      }
      else {
        // on the second thread, we've only made a deallocation, so it should NOT have any arena collections present
        assert(collection == nullptr);
      }
      assert(MemoryManager::thread_state.mm_alloc_error_status == 0);
      assert(MemoryManager::thread_state.mm_dealloc_error_status == 0);
      sandbox = sandbox->next;
    }
    assert(count_sandboxes == 2);
  }
  delete a;
  t1.join();
}

void MemoryManager::Test_ErrorHandling() {  
  // first find our thread sandbox
  ThreadSandboxNode* prev_sandbox = nullptr;
  if (!MemoryManager::thread_state.thread_id) {
    MemoryManager::thread_state.thread_id = GET_CURRENT_THREAD_ID();
  }
  // make an extremely large alloc with the default (exception throwing) version of new
  try {
    int64_t huge = 1000000000000000;
    char* c = new char[huge];
    assert(false); // we should never reach this if the exception was thrown
  } catch (std::bad_alloc e) {
    // good, we caught the exception
  }
  // make an extremely large alloc with the non-throwing version of new
  try {
    int64_t huge = 1000000000000000;
    char* c = new (std::nothrow) char[huge];
    assert(c == nullptr);
  }
  catch (std::bad_alloc e) {
    assert(false); // we should never reach this since no exceptions should be thrown
  }
}

void MemoryManager::PerfTest_AllocDealloc() {
  struct MMTestStructTiny {
    uint64_t thing1;
  };
  const int num_iters = 100;
  const int num_allocs = 1000;
  MMTestStructTiny* allocs[num_allocs];
  std::chrono::microseconds alloc_time = std::chrono::microseconds::zero();
  std::chrono::microseconds dealloc_time = std::chrono::microseconds::zero();
  long long shortest_alloc_time = 999999999;
  long long longest_alloc_time = 0;
  for (int j = 0; j < num_iters; ++j) {
    auto start_alloc = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < num_allocs; ++i) {
      allocs[i] = new MMTestStructTiny;
    }
    auto stop_alloc = std::chrono::high_resolution_clock::now();
    auto alloc_duration = std::chrono::duration_cast<std::chrono::microseconds>(stop_alloc - start_alloc);
    alloc_time = alloc_time + alloc_duration;
    if (alloc_duration.count() < shortest_alloc_time) {
      shortest_alloc_time = alloc_duration.count();
    }
    if (alloc_duration.count() > longest_alloc_time) {
      longest_alloc_time = alloc_duration.count();
    }
    auto start_dealloc = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < num_allocs; ++i) {
      delete allocs[i];
    }
    auto stop_dealloc = std::chrono::high_resolution_clock::now();
    auto dealloc_duration = std::chrono::duration_cast<std::chrono::microseconds>(stop_dealloc - start_dealloc);      
    dealloc_time = dealloc_time + dealloc_duration;
  }
  MEM_MGR_LOG("Alloc test took %lld microseconds, dealloc test took %lld microseconds. longest alloc time was %lld and shortest alloc time was %lld", alloc_time.count(), dealloc_time.count(), longest_alloc_time, shortest_alloc_time);
}
