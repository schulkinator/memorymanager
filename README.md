# memorymanager
A simple, cross-platform, thread-safe memory manager for C++ applications and games. Focus is on preventing fragmentation in the absence of good virtual memory management, at the cost of wasting a little bit of memory. It works by globally overriding the new and delete operators, so it "just works" as long as you use new and delete. No dependencies or special libraries required except the standard C++11 headers.

It attempts to keep allocations as contiguous in memory as possible by allocating memory arenas, which contain cells of memory. Deallocation is achieved by simply marking cells as "unoccupied" again. Actual free()-ing of memory back to the system is a rare event, so overall system memory use will tend to go up but seldomly go down as the memory manager holds on to this previously alloc()-ed memory to use for future allocations. Below is an example layout of the memory hierarchy within a single thread sandbox

![MemoryManager_toplevel](https://user-images.githubusercontent.com/14068824/113448154-23423200-93b0-11eb-9b6a-321815e12367.png)


The quickest way to use it with visual studio is to simply add the .h and .cpp files to your visual studio project alongside your source code.

Unit tests are included in the source as indicated.
