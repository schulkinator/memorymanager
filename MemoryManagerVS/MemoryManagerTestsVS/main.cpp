#include <stdio.h>
#include "MemoryManager.h"


int main(void) {

	MemoryManager::Test_StandardAllocDealloc();

	MemoryManager::Test_CrossThreadAllocDealloc();

	MemoryManager::Test_ErrorHandling();

	MemoryManager::Test_StochasticAllocDealloc();

	MemoryManager::PerfTest_AllocDealloc();

	return 0;
}