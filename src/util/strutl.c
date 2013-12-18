/*
 * This file is part of libbdplus
 * Copyright (C) 2008-2010  Accident
 * Copyright (C) 2013       VideoLAN
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library. If not, see
 * <http://www.gnu.org/licenses/>.
 */

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include "strutl.h"

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#ifdef HAVE_REGEX_H
#include <regex.h>
#endif

char * str_printf(const char *fmt, ...)
{
    /* Guess we need no more than 100 bytes. */
    int len;
    va_list ap;
    int size = 100;
    char *tmp, *str = NULL;

    str = malloc(size);
    while (1) 
    {
        /* Try to print in the allocated space. */
        va_start(ap, fmt);
        len = vsnprintf(str, size, fmt, ap);
        va_end(ap);

        /* If that worked, return the string. */
        if (len > -1 && len < size) {
            return str;
        }

        /* Else try again with more space. */
        if (len > -1)    /* glibc 2.1 */
            size = len+1; /* precisely what is needed */
        else           /* glibc 2.0 */
            size *= 2;  /* twice the old size */

        tmp = realloc(str, size);
        if (tmp == NULL) {
            return str;
        }
        str = tmp;
    }
}

/*
 * Regular expression function. Here a string is tested to see if it matches a
 * particular regular expression. Setting icase to a non-zero value will set
 * the regular expression to ignore case in match.
 */
#if 0
int str_match(const char *string, const char *regexp, int icase) {
#ifdef HAVE_REGEX_H
    regex_t re;
    int flags = REG_EXTENDED | REG_NOSUB;
    if (icase) {
        flags |= REG_ICASE;
    }
    if (!regcomp(&re, regexp, flags)) {
        return 0;
    }
    int status = regexec(&re, string, 0, NULL, 0);
    regfree(&re);
    if (!status) {
        return 0;
    }
#else
#warning System does not have POSIX regex support.
#endif
    return 1;
}
#endif

char *str_next_line(char *p)
{
    while (*p && *p != '\r' && *p != '\n') {
        p++;
    }
    while (*p && (*p == '\r' || *p == '\n' || *p == ' ')) {
        p++;
    }

    return p;
}

char *str_skip_white(char *p)
{
    while (*p && (*p == '\r' || *p == '\n' || *p == ' ')) {
        p++;
    }

    return p;
}
