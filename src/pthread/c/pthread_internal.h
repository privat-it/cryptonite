/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef PTHREAD_INTERNAL_H_
#define PTHREAD_INTERNAL_H_

#ifdef _WIN32
#include <windows.h>
#include <errno.h>

#define PTHREAD_CANCEL_ASYNCHRONOUS 1
#define PTHREAD_CANCEL_ENABLE       2
#define PTHREAD_CANCEL_DEFERRED     3
#define PTHREAD_CANCEL_DISABLE      4
#define PTHREAD_CANCELED            5
#define PTHREAD_COND_INITIALIZER    {0}
#define PTHREAD_CREATE_DETACHED     6
#define PTHREAD_CREATE_JOINABLE     7
#define PTHREAD_EXPLICIT_SCHED      8
#define PTHREAD_INHERIT_SCHED       9
#define PTHREAD_MUTEX_DEFAULT       {0}
#define PTHREAD_MUTEX_ERRORCHECK    {0}
#define PTHREAD_MUTEX_NORMAL        {0}
#define PTHREAD_MUTEX_INITIALIZER   {0}
#define PTHREAD_MUTEX_RECURSIVE     {0}
#define PTHREAD_ONCE_INIT           10
#define PTHREAD_PRIO_INHERIT        11
#define PTHREAD_PRIO_NONE           12
#define PTHREAD_PRIO_PROTECT        13
#define PTHREAD_PROCESS_SHARED      14
#define PTHREAD_PROCESS_PRIVATE     15
#define PTHREAD_RWLOCK_INITIALIZER  {0}
#define PTHREAD_SCOPE_PROCESS       16
#define PTHREAD_SCOPE_SYSTEM        17

typedef struct {
    HANDLE handle;
    unsigned int tid;
} pthread_t;

typedef struct {
    LPSECURITY_ATTRIBUTES threadAttributes;
    SIZE_T stackSize;
    void *stackAddr;
    DWORD creationFlags;
    int detachState;
    int contentionScope;
    int policy; /*supported values: SCHED_FIFO, SCHED_RR, and SCHED_OTHER*/
    int inheritSched;
    int detach;
} pthread_attr_t;

typedef struct {
    HANDLE mutex;
    int destroyed;
    int init;
    int lockedOrReferenced;
} pthread_mutex_t;

typedef struct {
    int protocol;
    int pShared;
    int prioCeiling;
    int type;
} pthread_mutexattr_t;

CRYPTONITE_EXPORT int  pthread_create(pthread_t *, const pthread_attr_t *, void *(*)(void *), void *);
CRYPTONITE_EXPORT int  pthread_cancel(pthread_t);
CRYPTONITE_EXPORT int  pthread_detach(pthread_t);
CRYPTONITE_EXPORT void pthread_exit(void *);
CRYPTONITE_EXPORT int  pthread_join(pthread_t, void **);
CRYPTONITE_EXPORT int  pthread_mutex_destroy(pthread_mutex_t *);
CRYPTONITE_EXPORT int  pthread_mutex_init(pthread_mutex_t *, const pthread_mutexattr_t *);
CRYPTONITE_EXPORT int  pthread_mutex_lock(pthread_mutex_t *);
CRYPTONITE_EXPORT int  pthread_mutex_unlock(pthread_mutex_t *);
#else

#include <pthread.h>
#include <unistd.h>
#endif /* _WIN32 */

CRYPTONITE_EXPORT unsigned long pthread_id(void);

#endif /* PTHREAD_INTERNAL_H_ */
