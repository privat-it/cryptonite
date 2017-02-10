/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#include "pthread_internal.h"

#undef FILE_MARKER
#define FILE_MARKER "cryptonite/pthread_impl.c"

#ifdef _WIN32
int pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*startup)(void *), void *params)
{
    DWORD threadid;
    HANDLE h;

    if (attr) {
        h = CreateThread(attr->threadAttributes,
                attr->stackSize,
                (DWORD (WINAPI *)(LPVOID))startup,
                params,
                attr->creationFlags,
                &threadid);
    } else {
        h = CreateThread(NULL,
                0,
                (DWORD (WINAPI *)(LPVOID))startup,
                params,
                0,
                &threadid);
    }

    thread->tid = threadid;

    if (!h) {
        return -1;
    }

    if (attr && (attr->detachState == PTHREAD_CREATE_DETACHED)) {
        CloseHandle(h);
    } else {
        thread->handle = h;
    }

    return 0;
}

void pthread_exit(void *value_ptr)
{
    if (value_ptr) {
        ExitThread(*(DWORD *)value_ptr);
    } else {
        ExitThread(0);
    }
}

int pthread_join(pthread_t thread, void **value_ptr)
{
    DWORD ret;

    if (!thread.handle) {
        return -1;
    }

    ret = WaitForSingleObject(thread.handle, INFINITE);
    if (ret == WAIT_FAILED) {
        return -1;
    } else if ((ret == WAIT_ABANDONED) || (ret == WAIT_OBJECT_0)) {
        if (value_ptr) {
            GetExitCodeThread(thread.handle, (LPDWORD)value_ptr);
        }
    }

    return 0;
}

int pthread_detach(pthread_t thread)
{
    if (!thread.handle) {
        return -1;
    }

    CloseHandle(thread.handle);
    thread.handle = 0;

    return 0;
}

int pthread_cancel(pthread_t thread)
{
    return 0;
}

int pthread_mutex_init(pthread_mutex_t *mutex, const pthread_mutexattr_t *attr)
{
    if (mutex) {
        if (mutex->init && !mutex->destroyed) {
            return EBUSY;
        }

        mutex->mutex = CreateMutex(NULL, FALSE, NULL);
        mutex->destroyed = 0;
        mutex->init = 1;
        mutex->lockedOrReferenced = 0;
    }

    return 0;
}

int pthread_mutex_lock(pthread_mutex_t *mutex)
{
    DWORD ret;

    if (!mutex) {
        return EINVAL;
    }

    if (!mutex->mutex) {
        pthread_mutex_init(mutex, NULL);
    }

    ret = WaitForSingleObject(mutex->mutex, INFINITE);

    if (ret != WAIT_FAILED) {
        mutex->lockedOrReferenced = 1;
        return 0;
    } else {
        return EINVAL;
    }
}

int pthread_mutex_unlock(pthread_mutex_t *mutex)
{
    DWORD ret;

    if (!mutex) {
        return EINVAL;
    }

    ret = ReleaseMutex(mutex->mutex);

    if (ret != 0) {
        mutex->lockedOrReferenced = 0;
        return 0;
    } else {
        return EPERM;
    }
}

int pthread_mutex_destroy(pthread_mutex_t *mutex)
{
    if (!mutex) {
        return EINVAL;
    }

    if (mutex->lockedOrReferenced) {
        return EBUSY;
    }

    mutex->destroyed = 1;

    return 0;
}
#endif

unsigned long pthread_id(void)
{
    unsigned long ret = 0;

#ifdef _WIN32
    ret = (unsigned long)GetCurrentThreadId();
#else
    ret = (unsigned long)pthread_self();
#endif

    return ret;
}
