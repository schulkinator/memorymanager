# memorymanager
A simple, cross-platform, thread-safe heap memory manager for C++ applications and games. Focus is on preventing fragmentation in the absence of good virtual memory management, at the cost of wasting a little bit of memory. It works by globally overriding the new and delete operators, so it "just works" as long as you use new and delete. No dependencies or special libraries required except the standard C++11 headers and windows headers if compiling on windows.

The Memory Manager attempts to keep allocations as contiguous in memory as possible by allocating memory arenas, which contain cells of memory. These "cells" of memory are what actually get reserved as the space for the call to new. All cells in an arena are the same size. An allocation will look across the arenas and find the smallest cell that is larger than the requested allocation. So if an allocation uses less memory than the cell size it will waste that remaining space inside the cell. Deallocation is extremely fast and is achieved by simply marking cells as "unoccupied" again (flipping a bit). Once a cell is marked as unoccupied it is available to be used for a new allocation and its contents can be overwritten with new data. 

Actual free()-ing of memory back to the OS is a rare event, so overall process memory use will tend to go up but seldomly go down as the memory manager holds on to this previously malloc()-ed memory to use for future allocations. This may seem like a bad thing to hold on to memory for that long without releasing it, but remember that our goal is to avoid fragmentation. The way to think about it is that this memory is "reserved" for your application to use over and over again as time goes on instead of releasing it back to the system repeatedly. Eventually your application should reach a plateau of maximum allocated arena memory, after which allocations will be made almost exclusively from those arenas. Problems could arise if there is a very large momentary memory allocation spike, generating a bunch of unused arenas, but this should also be mitigated by the fact that large allocations are made directly from the OS instead. You can decide where that threshold of "large" is, defined by MAX_CELL_SIZE.

Terminology: 

"Thread Sandbox" - A thread sandbox is simply the working space of memory that only one specific thread can touch. There can be as many thread sanboxes as there are number of threads in the application. We do this mostly so that each thread can avoid synchronization contention when accessing the memory that it allocates. Contention only arises when threads try to deallocate memory that was previously allocated on another thread. Therefore we have to track memory "ownership" per thread.

"Arena" - A contiguous chunk of memory which contains individual cells of memory

"Cell" - A single block of memory that is intended to be the smallest atomic unit for allocation managed by the memory manager. 
         aka. the memory used by application code

Below is an example layout of the memory hierarchy within a single thread sandbox

![MemoryManager_toplevel](https://user-images.githubusercontent.com/14068824/113484457-37903880-945d-11eb-985c-90c3fa4584df.png)

Below is an example detailed view of a single arena. Notice that the whole arena is one contiguous block of memory, including the header. Each arena has a specific capacity based on the cell size it contains. All cells in an arena are the same size. The cell capacity is determined based on the maximum arena size (defined by MAX_ARENA_SIZE) and the cell size for that arena. Additionally the cell capacity can be no larger than 64 cells, just so that we can track occupancy in a single 64 bit integer bitfield. So for example, if we have MAX_ARENA_SIZE set to 8MB, and we're allocating cells of size 1MB, then the arena will only contain 8 cells, each of size 1MB.

![MemoryManager_arena](https://user-images.githubusercontent.com/14068824/113484861-6ad3c700-945f-11eb-94d8-a7506e147a63.png)


The quickest way to use it with visual studio is to simply add the .h and .cpp files to your visual studio project alongside your source code.

Unit tests are included in the source as indicated.
