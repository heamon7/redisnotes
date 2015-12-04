/* zmalloc - total amount of allocated memory aware version of malloc()
 *
 * Copyright (c) 2009-2010, Salvatore Sanfilippo <antirez at gmail dot com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of Redis nor the names of its contributors may be used
 *     to endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>

/* This function provide us access to the original libc free(). This is useful
 * for instance to free results obtained by backtrace_symbols(). We need
 * to define this function before including zmalloc.h that may shadow the
 * free implementation if we use jemalloc or another non standard allocator. */
void zlibc_free(void *ptr) {
    free(ptr);
}
// heamon7: 没有自动保存真是伤啊，每天应该用git保存的啊，电脑居然这样崩了
#include <string.h>
#include <pthread.h>
#include "config.h"
#include "zmalloc.h"

// heamon7: 这个宏的定义在zmalloc.h中，Linux环境设置为1，作用是判断系统中是否提供有 malloc_size 这个函数，Linux是有的，通过man malloc_size我们知道
// heamon7: malloc_size的功能是获取malloc等返回的指针所指向的内存块的大小，而这个大小一般不会小于申请的大小
/* heamon7:
 * 下面要定义的宏是用于记录内存块大小的
 * CPU一次性能读取数据的二进制位数称为字长，也就是我们通常所说的32位系统（字长4个字节）、64位系统（字长8个字节）的由来。所谓的8字节对齐，
 * 就是指变量的起始地址是8的倍数。比如程序运行时（CPU）在读取long型数据的时候，只需要一个总线周期，时间更短，如果不是8字节对齐的则需要两个总线周期
 * 才能读完数据
 */
#ifdef HAVE_MALLOC_SIZE
#define PREFIX_SIZE (0)  // heamon7: 这里非常重要，后面频繁使用PREFIX_SIZE,因为系统提供了malloc_size这个函数，我们不需要再自己来记录内存块的大小
#else
#if defined(__sun) || defined(__sparc) || defined(__sparc__)
#define PREFIX_SIZE (sizeof(long long))
#else
#define PREFIX_SIZE (sizeof(size_t))
#endif
#endif

/* Explicitly override malloc/free etc when using tcmalloc. */
#if defined(USE_TCMALLOC)
#define malloc(size) tc_malloc(size)
#define calloc(count,size) tc_calloc(count,size)
#define realloc(ptr,size) tc_realloc(ptr,size)
#define free(ptr) tc_free(ptr)
#elif defined(USE_JEMALLOC)  // heamon7: 我们使用的是jemalloc，所以这里用的下面的宏函数来进行内存分配
#define malloc(size) je_malloc(size)
#define calloc(count,size) je_calloc(count,size)
#define realloc(ptr,size) je_realloc(ptr,size)
#define free(ptr) je_free(ptr)
#endif

// heamon7: 这里的HAVA_ATOMIC在config.c中定义的,根据GNUC的版本号，一般符合。下面定义的宏函数是统计内存使用的。
#ifdef HAVE_ATOMIC
#define update_zmalloc_stat_add(__n) __sync_add_and_fetch(&used_memory, (__n)) // heamon7: GNUC提供的线程安全的加法运算
#define update_zmalloc_stat_sub(__n) __sync_sub_and_fetch(&used_memory, (__n))  // heamon7: GNUC提供的线程安全的减法运算
#else
#define update_zmalloc_stat_add(__n) do { \
    pthread_mutex_lock(&used_memory_mutex); \
    used_memory += (__n); \
    pthread_mutex_unlock(&used_memory_mutex); \
} while(0)
#define update_zmalloc_stat_sub(__n) do { \
    pthread_mutex_lock(&used_memory_mutex); \
    used_memory -= (__n); \
    pthread_mutex_unlock(&used_memory_mutex); \
} while(0)
#endif


#define update_zmalloc_stat_alloc(__n) do { \
    size_t _n = (__n); \  // heamon7: 下面这个条件只有在_n是8的倍数的时候才为假，而一般_n肯定是对齐的，也就是肯定为假
    if (_n&(sizeof(long)-1)) _n += sizeof(long)-(_n&(sizeof(long)-1)); \  // heamon7: _n&7相当于_n%8,但是快很多
    if (zmalloc_thread_safe) { \  // heamon7: 默认没有启动线程安全
        update_zmalloc_stat_add(_n); \
    } else { \
        used_memory += _n; \
    } \
} while(0)

#define update_zmalloc_stat_free(__n) do { \
    size_t _n = (__n); \
    if (_n&(sizeof(long)-1)) _n += sizeof(long)-(_n&(sizeof(long)-1)); \
    if (zmalloc_thread_safe) { \
        update_zmalloc_stat_sub(_n); \
    } else { \
        used_memory -= _n; \
    } \
} while(0)

// heamon7: 这里揭示了非常重要的一点，默认是没有启动线程安全的，也就是说redis是一个单线程的程序，而之所以能有如此高的并发，原因在于使用了
// heamon7: 提高并发的三种方法中的 多路I/O复用技术。迅速的原因在于 数据全部在内存里，完全不需要访问磁盘
// heamon7: 参考： [单线程的redis为何会有如此好的性能](http://segmentfault.com/q/1010000000666417)
// heamon7: [单线程多路复用和多线程加锁的区别](http://segmentfault.com/q/1010000004026316)
// heamon7: [快在哪里呢？EPOLL？内存](http://www.zhihu.com/question/19764056)
// heamon7: [I/O多路复用技术（multiplexing）是什么？](http://www.zhihu.com/question/28594409)
// heamon7: [Redis为什么是单线程?](http://cloudate.net/?p=222)

static size_t used_memory = 0;  // heamon7: 定义的全局变量，用于统计记录使用的内存
static int zmalloc_thread_safe = 0; // heamon7: ？为什么默认没有启动线程安全呢？作用就是表示是否启用线程安全，默认没有启用线程安全
pthread_mutex_t used_memory_mutex = PTHREAD_MUTEX_INITIALIZER;  // heamon7:  线程锁，用来在统计时对全局变量used_memory进行加锁

// heamon7: oom 是 out of memory 的意思，这里定义了内存不够，分配失败的默认处理函数，打印错误，并且终止程序
static void zmalloc_default_oom(size_t size) {
    fprintf(stderr, "zmalloc: Out of memory trying to allocate %zu bytes\n",
        size);
    fflush(stderr);
    abort();
}

static void (*zmalloc_oom_handler)(size_t) = zmalloc_default_oom;

void *zmalloc(size_t size) {
    void *ptr = malloc(size+PREFIX_SIZE);   // heamon7: 这里PREFIX_SIZE的值为0

    if (!ptr) zmalloc_oom_handler(size);  // heamon7: 如果分配内存失败，就打印错误信息并终止程序
#ifdef HAVE_MALLOC_SIZE  // heamon7: 感觉如果定义了这个宏的时候，好像是表明，返回的ptr本身就是已经经过了下面的记录size大小的，并且右移的地址
    update_zmalloc_stat_alloc(zmalloc_size(ptr)); // heamon7: 注意这里的zmalloc_size是使用jemalloc提供的，并不是下面我们定义的，
    return ptr;  // heamon7: 而是在zmalloc.h中定义的,返回分配给我们的内存块的block_size, 这个block_size 总是大于等于要求分配的size
#else  // heamon7: 这里一般并不会执行到
    *((size_t*)ptr) = size;  // heamon7: 在已分配内存的第一个字长处存储分配空间的字节大小
    update_zmalloc_stat_alloc(size+PREFIX_SIZE);  // heamon7: 这里是在更新统计使用内存的全局变量，used_memory
    return (char*)ptr+PREFIX_SIZE;  // heamon7: 这里返回ptr右边偏移一个字长处的地址，这个地址返回给调用者
#endif
}

// heamon7: 这里zcalloc改变了calloc的接口，和zmalloc相比，编程接口是一样的，只是完成了分配空间的初始化工作
void *zcalloc(size_t size) {
    void *ptr = calloc(1, size+PREFIX_SIZE);  // heamon7: 注意默认是1个obj，每个obj的size是size

    if (!ptr) zmalloc_oom_handler(size);
#ifdef HAVE_MALLOC_SIZE
    update_zmalloc_stat_alloc(zmalloc_size(ptr));
    return ptr;
#else
    *((size_t*)ptr) = size;
    update_zmalloc_stat_alloc(size+PREFIX_SIZE);
    return (char*)ptr+PREFIX_SIZE;
#endif
}
// heamon7: zrealloc的编程接口和
void *zrealloc(void *ptr, size_t size) {
#ifndef HAVE_MALLOC_SIZE
    void *realptr;
#endif
    size_t oldsize;
    void *newptr;

    if (ptr == NULL) return zmalloc(size);
#ifdef HAVE_MALLOC_SIZE
    oldsize = zmalloc_size(ptr);
    newptr = realloc(ptr,size);
    if (!newptr) zmalloc_oom_handler(size);

    update_zmalloc_stat_free(oldsize);
    update_zmalloc_stat_alloc(zmalloc_size(newptr));
    return newptr;
#else
    realptr = (char*)ptr-PREFIX_SIZE;
    oldsize = *((size_t*)realptr);
    newptr = realloc(realptr,size+PREFIX_SIZE);
    if (!newptr) zmalloc_oom_handler(size);

    *((size_t*)newptr) = size;
    update_zmalloc_stat_free(oldsize);
    update_zmalloc_stat_alloc(size);
    return (char*)newptr+PREFIX_SIZE;
#endif
}

/* Provide zmalloc_size() for systems where this function is not provided by
 * malloc itself, given that in that case we store an header with this
 * information as the first bytes of every allocation. */
// heamon7: 通过 man malloc_size ，我们知道了malloc_size可以返回指向了分配的内存块的大小，但是有些系统并没有实现这个函数，
// heamon7: 对于那些没有实现这个函数的，我们需要自己来实现这个函数,系统有没有提供是通过zmalloc.h中定义的宏HAVE_MALLOC_SIZE说明的

#ifndef HAVE_MALLOC_SIZE
size_t zmalloc_size(void *ptr) {
    void *realptr = (char*)ptr-PREFIX_SIZE;
    size_t size = *((size_t*)realptr);
    /* Assume at least that all the allocations are padded at sizeof(long) by
     * the underlying allocator. */
    // heamon7: 如果size的值和sizeof(long)的值相等，那么条件为假，当size增加2^4时，貌似也为0
    if (size&(sizeof(long)-1)) size += sizeof(long)-(size&(sizeof(long)-1));
    return size+PREFIX_SIZE;
}
#endif

void zfree(void *ptr) {
#ifndef HAVE_MALLOC_SIZE
    void *realptr;
    size_t oldsize;
#endif

    if (ptr == NULL) return;
#ifdef HAVE_MALLOC_SIZE
    update_zmalloc_stat_free(zmalloc_size(ptr));
    free(ptr);
#else
    realptr = (char*)ptr-PREFIX_SIZE;
    oldsize = *((size_t*)realptr);
    update_zmalloc_stat_free(oldsize+PREFIX_SIZE);
    free(realptr);
#endif
}

char *zstrdup(const char *s) {
    size_t l = strlen(s)+1;
    char *p = zmalloc(l);

    memcpy(p,s,l);
    return p;
}

size_t zmalloc_used_memory(void) {
    size_t um;

    if (zmalloc_thread_safe) {
#ifdef HAVE_ATOMIC
        um = __sync_add_and_fetch(&used_memory, 0);
#else
        pthread_mutex_lock(&used_memory_mutex);
        um = used_memory;
        pthread_mutex_unlock(&used_memory_mutex);
#endif
    }
    else {
        um = used_memory;
    }

    return um;
}

void zmalloc_enable_thread_safeness(void) {
    zmalloc_thread_safe = 1;
}

void zmalloc_set_oom_handler(void (*oom_handler)(size_t)) {
    zmalloc_oom_handler = oom_handler;
}

/* Get the RSS information in an OS-specific way.
 *
 * WARNING: the function zmalloc_get_rss() is not designed to be fast
 * and may not be called in the busy loops where Redis tries to release
 * memory expiring or swapping out objects.
 *
 * For this kind of "fast RSS reporting" usages use instead the
 * function RedisEstimateRSS() that is a much faster (and less precise)
 * version of the funciton. */

#if defined(HAVE_PROC_STAT)
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

size_t zmalloc_get_rss(void) {
    int page = sysconf(_SC_PAGESIZE);
    size_t rss;
    char buf[4096];
    char filename[256];
    int fd, count;
    char *p, *x;

    snprintf(filename,256,"/proc/%d/stat",getpid());
    if ((fd = open(filename,O_RDONLY)) == -1) return 0;
    if (read(fd,buf,4096) <= 0) {
        close(fd);
        return 0;
    }
    close(fd);

    p = buf;
    count = 23; /* RSS is the 24th field in /proc/<pid>/stat */
    while(p && count--) {
        p = strchr(p,' ');
        if (p) p++;
    }
    if (!p) return 0;
    x = strchr(p,' ');
    if (!x) return 0;
    *x = '\0';

    rss = strtoll(p,NULL,10);
    rss *= page;
    return rss;
}
#elif defined(HAVE_TASKINFO)
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <mach/task.h>
#include <mach/mach_init.h>

size_t zmalloc_get_rss(void) {
    task_t task = MACH_PORT_NULL;
    struct task_basic_info t_info;
    mach_msg_type_number_t t_info_count = TASK_BASIC_INFO_COUNT;

    if (task_for_pid(current_task(), getpid(), &task) != KERN_SUCCESS)
        return 0;
    task_info(task, TASK_BASIC_INFO, (task_info_t)&t_info, &t_info_count);

    return t_info.resident_size;
}
#else
size_t zmalloc_get_rss(void) {
    /* If we can't get the RSS in an OS-specific way for this system just
     * return the memory usage we estimated in zmalloc()..
     *
     * Fragmentation will appear to be always 1 (no fragmentation)
     * of course... */
    return zmalloc_used_memory();
}
#endif

/* Fragmentation = RSS / allocated-bytes */
float zmalloc_get_fragmentation_ratio(void) {
    return (float)zmalloc_get_rss()/zmalloc_used_memory();
}

#if defined(HAVE_PROC_SMAPS)
size_t zmalloc_get_private_dirty(void) {
    char line[1024];
    size_t pd = 0;
    FILE *fp = fopen("/proc/self/smaps","r");

    if (!fp) return 0;
    while(fgets(line,sizeof(line),fp) != NULL) {
        if (strncmp(line,"Private_Dirty:",14) == 0) {
            char *p = strchr(line,'k');
            if (p) {
                *p = '\0';
                pd += strtol(line+14,NULL,10) * 1024;
            }
        }
    }
    fclose(fp);
    return pd;
}
#else
size_t zmalloc_get_private_dirty(void) {
    return 0;
}
#endif

/* heamon7: 参考文献：
 * - [ Redis内存管理的基石zmallc.c源码解读（一）](http://blog.csdn.net/guodongxiaren/article/details/44747719)
 * - [Redis内存管理的基石zmallc.c源码解读（二）](http://blog.csdn.net/guodongxiaren/article/details/44783767)
 * - [Redis 内存管理示意图 ](https://www.processon.com/view/551f9419e4b039866d18dd99)
 * - [Redis 内存数据管理](http://wiki.jikexueyuan.com/project/redis/memory-data-management.html)
 * - []
 */
