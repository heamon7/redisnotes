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
    pthread_mutex_lock(&used_memory_mutex); \ // heamon7: 加锁和解锁
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

/* heamon7: 这里揭示了非常重要的一点，默认是没有启动线程安全的，也就是说redis是一个单线程的程序，而之所以能有如此高的并发，原因在于使用了
 * 提高并发的三种方法中的 多路I/O复用技术。迅速的原因在于 数据全部在内存里，完全不需要访问磁盘
 * 参考： [单线程的redis为何会有如此好的性能](http://segmentfault.com/q/1010000000666417)
 * [单线程多路复用和多线程加锁的区别](http://segmentfault.com/q/1010000004026316)
 * [快在哪里呢？EPOLL？内存](http://www.zhihu.com/question/19764056)
 * [I/O多路复用技术（multiplexing）是什么？](http://www.zhihu.com/question/28594409)
 * [Redis为什么是单线程?](http://cloudate.net/?p=222)
 */
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
#ifdef HAVE_MALLOC_SIZE  // heamon7: 统计分配的内存
    update_zmalloc_stat_alloc(zmalloc_size(ptr));
    return ptr;
#else // heamon7: 不会执行
    *((size_t*)ptr) = size;
    update_zmalloc_stat_alloc(size+PREFIX_SIZE);
    return (char*)ptr+PREFIX_SIZE;
#endif
}
// heamon7: zrealloc的编程接口和realloc的接口是一样的，
void *zrealloc(void *ptr, size_t size) {
#ifndef HAVE_MALLOC_SIZE
    void *realptr;
#endif
    size_t oldsize;
    void *newptr;

    if (ptr == NULL) return zmalloc(size);  // heamon7: 如果传入的是空指针，则直接调用zmalloc新分配一个空间，并返回地址指针
#ifdef HAVE_MALLOC_SIZE
    oldsize = zmalloc_size(ptr); // heamon7: 记录重分配前的空间大小
    newptr = realloc(ptr,size);  // heamon7: 重新分配空间，返回新的地址
    if (!newptr) zmalloc_oom_handler(size);  // heamon7: 分配失败处理

    update_zmalloc_stat_free(oldsize);  // heamon7: 统计释放的内存块（ptr也可能并没有被释放掉，可能是减少）
    update_zmalloc_stat_alloc(zmalloc_size(newptr));  // heamon7: ？统计分配的内存块,可是在zmalloc里面不是已经统计过了吗？
    return newptr;
#else  // heamon7: linux不会执行
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
    // heamon7: 如果ptr指向的内存块不是8的倍数，则要进行对齐
    if (size&(sizeof(long)-1)) size += sizeof(long)-(size&(sizeof(long)-1));
    return size+PREFIX_SIZE;
}
#endif

// heamon7: 和free的编程接口一致，释放内存
void zfree(void *ptr) {
#ifndef HAVE_MALLOC_SIZE
    void *realptr;
    size_t oldsize;
#endif

    if (ptr == NULL) return;
#ifdef HAVE_MALLOC_SIZE  // heamon7: 统计释放内存的大小，然后释放
    update_zmalloc_stat_free(zmalloc_size(ptr));
    free(ptr);
#else
    realptr = (char*)ptr-PREFIX_SIZE;
    oldsize = *((size_t*)realptr);
    update_zmalloc_stat_free(oldsize+PREFIX_SIZE);
    free(realptr);
#endif
}

// heamon7: 通过man strdup ，这个函数把字符串s复制到堆内存，然后返回相应的堆地址
char *zstrdup(const char *s) {
    size_t l = strlen(s)+1;  // heamon7: 得到字符串长度，strlen不包括\0,所以加1
    char *p = zmalloc(l);
    memcpy(p,s,l);  // heamon7: 使用memcpy来复制字符串，（会不会不安全呢？）
    return p;
}

// heamon7: 返回使用的内存量,通过返回全局静态变量used_memory
size_t zmalloc_used_memory(void) {
    size_t um;
    if (zmalloc_thread_safe) {
#ifdef HAVE_ATOMIC
        um = __sync_add_and_fetch(&used_memory, 0);
#else
        pthread_mutex_lock(&used_memory_mutex); // heamon7: 这里如果启用了线程安全的话，实现线程同步是使用互斥锁，加锁然后解锁
        um = used_memory;
        pthread_mutex_unlock(&used_memory_mutex);
#endif
    } // heamon7: 这里直接返回used_memory
    else {
        um = used_memory;
    }
    return um;
}
// heamon7: 启用线程安全的函数，通过操作全局静态变量zmalloc_thread_safe
void zmalloc_enable_thread_safeness(void) {
    zmalloc_thread_safe = 1;
}
// heamon7: 分配内存失败的处理函数，注意 zmalloc_oom_handler 是一个函数指针
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

// heamon7: 这个宏是在config.h中定义了，是proc filesystem 相关的，linux条件成立
#if defined(HAVE_PROC_STAT)
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

/* heamon7:
 * 获取RSS的大小，这个RSS可不是我们在网络上常常看到的RSS，而是指的Resident Set Size，表示当前进程实际所驻留在内存中的空间大小，即不包括被交换（swap）出去的空间。
 * 我们所申请的内存空间不会全部常驻内存，系统会把其中一部分暂时不用的部分从内存中置换到swap区.
 * 通过[man proc](http://man7.org/linux/man-pages/man5/proc.5.html)，我们知道/proc[pid]/stat这个文件的第24个字段的rss信息，单位是pages（内存页数）
 */
size_t zmalloc_get_rss(void) {
    int page = sysconf(_SC_PAGESIZE);  // heamon7: 通过 man sysconf，我们知道这个函数可以获得一些系统的参数，这里是获得一页内存的大小，单位是字节，这里是4096 Byte
    size_t rss;
    char buf[4096];  // heamon7: 申请缓存
    char filename[256];  // heamon7: 用于存储文件名
    int fd, count;
    char *p, *x;

    snprintf(filename,256,"/proc/%d/stat",getpid()); // heamon7: 通过查看snprintf的用法，我们知道它最多返回有255个字符的字符串到filename中
    if ((fd = open(filename,O_RDONLY)) == -1) return 0; // heamon7: 读取filename这个文件，并返回文件描述符到fd，注意fd就是一个整数，如果读失败，就返回
    if (read(fd,buf,4096) <= 0) { // heamon7: 通过 [man read ](http://man7.org/linux/man-pages/man2/read.2.html),知道这里从fd中最多读4096个字符到buf中
        close(fd); // heamon7: 如果失败，关闭fd，并返回
        return 0;
    }
    close(fd);

    p = buf;
    count = 23; /* RSS is the 24th field in /proc/<pid>/stat */
    while(p && count--) {
        p = strchr(p,' '); // heamon7: 通过 [man strchr ](http://man7.org/linux/man-pages/man3/strchr.3.html) ,返回字符串s中第一次出现字符c的地址指针
        if (p) p++;  // heamon7: 注意这里有把p右移了一位，指向了空格之后
    }
    if (!p) return 0;  // heamon7: 如果遍历完了23个空格，到了字符串的结尾，则返回
    x = strchr(p,' '); //heamon7: x指向第24个字段的结尾
    if (!x) return 0;
    *x = '\0'; // heamon7: 设置字符串终止标志

    rss = strtoll(p,NULL,10); // heamon7: 通过[man strtoll](http://man7.org/linux/man-pages/man3/strtol.3.html),我们知道,这里是把这个字段转成一个long long型
    rss *= page;  // heamon7: 内存大小等于页数乘以每页大小
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

/* heamon7:
 * 这个函数是查询内存内部碎片率（fragmentation ratio），即RSS和所分配总内存空间的比值。
 * 内存碎片分为：内部碎片和外部碎片
 * 内部碎片：是已经被分配出去（能明确指出属于哪个进程）却不能被利用的内存空间，直到进程释放掉，才能被系统利用；
 * 外部碎片：是还没有被分配出去（不属于任何进程），但由于太小了无法分配给申请内存空间的新进程的内存空闲区域。
 */

/* Fragmentation = RSS / allocated-bytes */
float zmalloc_get_fragmentation_ratio(void) {
    return (float)zmalloc_get_rss()/zmalloc_used_memory();
}

/* heamon7: 这个宏是在config.h中定义了，是proc filesystem 相关的，linux条件成立
 * /proc/self/smaps 和 /proc/[pid]/smaps是等同的，self/ 表示的是当前进程的状态目录。而smaps文件中记录着该进程每一个映像消耗的内存相关信息，该文件内部由多个结构相同的块组成
 * 00400000-0048a000 r-xp 00000000 fd:03 960637       /bin/bash
                  Size:                552 kB
                  Rss:                 460 kB
                  Pss:                 100 kB
                  Shared_Clean:        452 kB
                  Shared_Dirty:          0 kB
                  Private_Clean:         8 kB
                  Private_Dirty:         0 kB
                  Referenced:          460 kB
                  Anonymous:             0 kB
                  AnonHugePages:         0 kB
                  Swap:                  0 kB
                  KernelPageSize:        4 kB
                  MMUPageSize:           4 kB
                  Locked:                0 kB
 * Rss=Shared_Clean+Shared_Dirty+Private_Clean+Private_Dirty
  其中：
Shared_Clean:多进程共享的内存，且其内容未被任意进程修改
Shared_Dirty:多进程共享的内存，但其内容被某个进程修改
Private_Clean:某个进程独享的内存，且其内容没有修改
Private_Dirty:某个进程独享的内存，但其内容被该进程修改
其实所谓的共享的内存，一般指的就是Unix系统中的共享库（.so文件）的使用，共享库又叫动态库（含义同Windows下的.dll文件），它只有在程序运行时才被装入内存。
这时共享库中的代码和数据可能会被多个进程所调用，于是就会产生共享（Shared）与私有（Private）、干净（Clean）与脏（Dirty）的区别了。此外该处所说的共享的内存除了包括共享库以外，
还包括System V的IPC机制之一的共享内存段（shared memory）
 */
#if defined(HAVE_PROC_SMAPS)
size_t zmalloc_get_private_dirty(void) {
    char line[1024];  // heamon7: 申请缓冲区
    size_t pd = 0;
    FILE *fp = fopen("/proc/self/smaps","r"); // heamon7: 只读打开文件
    if (!fp) return 0;
/* heamon7:
 * 通过[man fgets](http://man7.org/linux/man-pages/man3/fgets.3.html),知道fgets每次最多读取size-1个字符，并且遇到换行和文件结束就会停止，换行和结束符也存储
 * ，失败时返回null,成功时返回s，这里相当于就是在每次读取一行
 */
    while(fgets(line,sizeof(line),fp) != NULL) {
        if (strncmp(line,"Private_Dirty:",14) == 0) { // heamon7: 每次读到以 "Private_Dirty:" 开头的行的时候
            char *p = strchr(line,'k');  // heamon7: 就找到这一行的k的前面，也就是数字的后面
            if (p) {
                *p = '\0';  // heamon7: 设置字符串终止字符
                pd += strtol(line+14,NULL,10) * 1024;  // heamon7: 将这个数字量的字符串转成long
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
 * - [redis源码分析之内存布局](http://mingxinglai.com/cn/2015/06/memory-layout-of-redis/)
 */
