# memorymanager
A simple, thread-safe memory manager for C++ applications and games. Focus is on preventing fragmentation in the absence of good virtual memory management, at the cost of wasting some memory. It works by globally overriding the new and delete operators.

The quickest way to use it with visual studio is to simply add the .h and .cpp files to your visual studio project alongside your source code.

Unit tests are included in the source as indicated.
