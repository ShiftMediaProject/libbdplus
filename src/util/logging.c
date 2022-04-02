/*
 * This file is part of libbdplus
 * Copyright (C) 2008-2010  Accident
 * Copyright (C) 2009-2010  Obliter0n
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

#include "logging.h"

#include "file/file.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

uint32_t debug_mask = (uint32_t)-1; /* set all bits to make sure bd_debug() is called for initialization */

void bd_debug(const char *file, int line, uint32_t mask, const char *format, ...)
{
    static int   debug_init = 0;
    static FILE *logfile    = NULL;

    // Only call getenv() once.
    if (!debug_init) {
        debug_init = 1;
        logfile = stderr;

        char *env = NULL;
        if (debug_mask == (uint32_t)-1) {
            /* might be set by application with bd_set_debug_mask() */
            debug_mask = DBG_CRIT;
        }
        if ((env = getenv("BD_DEBUG_MASK")))
            debug_mask = strtol(env, NULL, 0);

        // Send DEBUG to file?
        if ((env = getenv("BDPLUS_DEBUG_FILE"))) {
            FILE *fp = fopen(env, "wb");
            if (fp) {
                logfile = fp;
                setvbuf(logfile, NULL, _IONBF, 0);
            } else {
                fprintf(logfile, "%s:%d: Error opening log file %s\n", __FILE__, __LINE__, env);
            }
        }
    }

    if (mask & debug_mask) {
        const char *f = strrchr(file, DIR_SEP_CHAR);
        char buffer[4096], *pt = buffer;
        va_list args;

        pt += sprintf(buffer, "%s:%d: ", f ? f + 1 : file, line);

        va_start(args, format);
        vsnprintf(pt, sizeof(buffer) - (size_t)(intptr_t)(pt - buffer) - 1, format, args);
        va_end(args);

        fprintf(logfile, "%s", buffer);
    }
}
