/*
 * Copyright (c) 2016 PrivatBank IT <acsk@privatbank.ua>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */

#ifndef _DIRENT_COMMON_H_
#define _DIRENT_COMMON_H_

#include <stdbool.h>

#if defined _WIN32

#ifdef __cplusplus
extern "C"
{
#endif

typedef struct DIR DIR;

struct dirent {
    char *d_name;
};

DIR           *opendir(const char *);
int           closedir(DIR *);
struct dirent *readdir(DIR *);
void          rewinddir(DIR *);

#ifdef __cplusplus
}
#endif

#else
#  ifdef __unix__
#    define _INCLUDE_POSIX_SOURCE
#endif /* __unix__ */
#  include <dirent.h>
#endif /* _WIN32 */

bool is_dir(const char *path);

#endif /* _DIRENT_COMMON_H_ */
