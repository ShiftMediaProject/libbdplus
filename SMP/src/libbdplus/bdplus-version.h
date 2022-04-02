/*
 * This file is part of libbdplus
 * Copyright (C) 2013 VideoLAN
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

#ifndef BDPLUS_VERSION_H_
#define BDPLUS_VERSION_H_

#define BDPLUS_VERSION_CODE(major, minor, micro) \
    (((major) * 10000) +                         \
     ((minor) *   100) +                         \
     ((micro) *     1))

#define BDPLUS_VERSION_MAJOR 0
#define BDPLUS_VERSION_MINOR 2
#define BDPLUS_VERSION_MICRO 0

#define BDPLUS_VERSION_STRING "0.2.0"

#define BDPLUS_VERSION \
    BDPLUS_VERSION_CODE(BDPLUS_VERSION_MAJOR, BDPLUS_VERSION_MINOR, BDPLUS_VERSION_MICRO)

#endif /* BDPLUS_VERSION_H_ */
