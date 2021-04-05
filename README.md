# memorymanager
A simple, cross-platform, thread-safe memory manager for C++ applications and games. Focus is on preventing fragmentation in the absence of good virtual memory management, at the cost of wasting a little bit of memory. It works by globally overriding the new and delete operators, so it "just works" as long as you use new and delete. No dependencies or special libraries required except the standard C++11 headers.

It attempts to keep allocations as contiguous in memory as possible by allocating memory arenas, which contain cells of memory. These "cells" of memory are what actually get reserved as the space for the call to new. Deallocation is achieved by simply marking cells as "unoccupied" again. Actual free()-ing of memory back to the system is a rare event, so overall system memory use will tend to go up but seldomly go down as the memory manager holds on to this previously malloc()-ed memory to use for future allocations. Below is an example layout of the memory hierarchy within a single thread sandbox

![MemoryManager_toplevel](https://user-images.githubusercontent.com/14068824/113484457-37903880-945d-11eb-985c-90c3fa4584df.png)

Below is an example detailed view of a single arena. Notice that the whole arena is one contiguous block of memory, including the header. Each arena has a specific capacity based on the cell size it contains. All cells in an arena are the same size. The cell capacity is determined based on the maximum arena size and the cell size. The cell capacity can be no larger than 64 cells, just so that we can track occupancy in a single 64 bit integer bitfield.

![MemoryManager_arena](https://user-images.githubusercontent.com/14068824/113484861-6ad3c700-945f-11eb-94d8-a7506e147a63.png)


The quickest way to use it with visual studio is to simply add the .h and .cpp files to your visual studio project alongside your source code.

Unit tests are included in the source as indicated.
