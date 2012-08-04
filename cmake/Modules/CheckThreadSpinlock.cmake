if(NOT CMAKE_USE_PTHREADS_INIT)
    return()
endif()

include(CheckCSourceCompiles)
set(CMAKE_REQUIRED_LIBRARIES ${CMAKE_THREAD_LIBS_INIT} ${CMAKE_THREAD_LIBS})
check_c_source_compiles("#include <pthread.h>
int main()
{
    pthread_spinlock_t lock;
    pthread_spin_init(&lock, 0);
}" HAVE_PTHREAD_SPINLOCK)
unset(CMAKE_REQUIRED_LIBRARIES)
if (HAVE_PTHREAD_SPINLOCK)
    add_definitions(-DHAVE_PTHREAD_SPINLOCK=1)
    message(STATUS "pthreads have spinlock")
endif()
