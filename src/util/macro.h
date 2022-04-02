/*
 * This file is part of libbluray
 * Copyright (C) 2009-2010  Obliter0n
 * Copyright (C) 2009-2010  John Stebbins
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

#ifndef MACRO_H_
#define MACRO_H_

#include <stdlib.h>  /* free() */

#define MKINT_BE16(X) ( (X)[0] << 8 | (X)[1] )
#define MKINT_BE24(X) ( (X)[0] << 16 | (X)[1] << 8 | (X)[2] )
#define MKINT_BE32(X) ( (unsigned)((X)[0]) << 24 | (X)[1] << 16 |  (X)[2] << 8 | (X)[3] )
#define X_FREE(X)     ( free(X), X = NULL )

#define BD_MIN(a,b) ((a)<(b)?(a):(b))
#define BD_MAX(a,b) ((a)>(b)?(a):(b))

/*
 *
 */

// endian safe fetch

//#define FETCH4(X) (uint32_t)(((uint32_t)(X)[0]<<24)|(X)[1]<<16|(X)[2]<<8|(X)[3])
static inline uint32_t FETCH4(const void *pv) {
  const uint8_t *p = pv;
  return (uint32_t)p[0] << 24 | p[1] << 16 | p[2] << 8 | p[3];
}

//#define FETCHU2(X) (uint32_t)((uint16_t)(((X)[0]<<8)|(X)[1]))
static inline uint32_t FETCHU2(const void *pv) {
  const uint8_t *p = pv;
  return (uint32_t)p[0] << 8 | p[1];
}

// Sign extended version
//#define FETCHS2(X) (int32_t)((int16_t)(((X)[0]<<8)|(X)[1]))
static inline int32_t FETCHS2(const void *pv) {
  return (int32_t)(int16_t)FETCHU2(pv);
}

//#define STORE2(X, Y) (X)[1]=(((Y))&0xff);(X)[0]=(((Y)>>8)&0xff);
static inline void STORE2(void *pv, uint32_t v) {
  uint8_t *p = pv;
  p[1] = v;
  p[0] = v >> 8;
}
//#define STORE4(X, Y) (X)[3]=((Y)&0xff);(X)[2]=(((Y)>>8)&0xff);(X)[1]=(((Y)>>16)&0xff);(X)[0]=(((Y)>>24)&0xff);
static inline void STORE4(void *pv, uint32_t v) {
  uint8_t *p = pv;
  STORE2(p + 2, v);
  STORE2(p,     v >> 16);
}
//#define STORE8(X, Y) (X)[7]=((Y)&0xff);(X)[6]=(((Y)>>8)&0xff);(X)[5]=(((Y)>>16)&0xff);(X)[4]=(((Y)>>24)&0xff);(X)[3]=(((Y)>>32)&0xff);(X)[2]=(((Y)>>40)&0xff);(X)[1]=(((Y)>>48)&0xff);(X)[0]=(((Y)>>56)&0xff);
static inline void STORE8(void *pv, uint64_t v) {
  uint8_t *p = pv;
  STORE4(p + 4, v);
  STORE4(p,     v >> 32);
}

#define BD_MAX_SSIZE ((int64_t)(((size_t)-1)>>1))

/*
 * automatic cast from void* (malloc/calloc/realloc)
 */

#ifdef __cplusplus

template <typename T>
class auto_cast_wrapper
{
public:
    template <typename R> friend auto_cast_wrapper<R> auto_cast(const R& x);
    template <typename U> operator U() { return static_cast<U>(p); }

private:
    auto_cast_wrapper(const T& x) : p(x) {}
    auto_cast_wrapper(const auto_cast_wrapper& o) : p(o.p) {}

    auto_cast_wrapper& operator=(const auto_cast_wrapper&);

    const T& p;
};

template <typename R>
auto_cast_wrapper<R> auto_cast(const R& x)
{
    return auto_cast_wrapper<R>(x);
}

#  define calloc(n,s)  auto_cast(calloc(n,s))
#  define malloc(s)    auto_cast(malloc(s))
#  define realloc(p,s) auto_cast(realloc(p,s))
#  define refcnt_realloc(p,s) auto_cast(refcnt_realloc(p,s))
#endif /* __cplusplus */


#endif /* MACRO_H_ */
