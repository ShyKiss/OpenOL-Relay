/*=============================================================================
    relay_compat.h — MSVC VS2012 polyfills for snprintf / inet_pton / inet_ntop

    Must be included AFTER winsock2.h / ws2tcpip.h so AF_INET etc. are visible.
    Windows SDK 8.0+ (ws2tcpip.h) already provides inet_pton/inet_ntop — guard
    against redefinition using the SDK's own include guard.
=============================================================================*/
#pragma once

#if defined(_MSC_VER) && _MSC_VER < 1900

#include <stdio.h>
#include <stdarg.h>
#include <string.h>

/* snprintf — always needed, MSVC < 1900 has none. */
#ifndef relay_snprintf_defined
#define relay_snprintf_defined
static __inline int relay_snprintf(char *buf, size_t sz, const char *fmt, ...) {
    int r;
    va_list ap;
    va_start(ap, fmt);
    r = _vsnprintf(buf, sz, fmt, ap);
    va_end(ap);
    if (sz > 0) buf[sz - 1] = '\0';
    return r;
}
#endif
#define snprintf relay_snprintf

/* inet_pton / inet_ntop — Windows SDK 8.0 (ws2tcpip.h) defines these as
   inline functions guarded by _WS2TCPIP_H_. Only provide polyfills when
   that header has NOT been included. */
#ifndef _WS2TCPIP_H_

#ifndef relay_inet_pton_defined
#define relay_inet_pton_defined
static __inline int relay_inet_pton(int af, const char *src, void *dst) {
    unsigned long addr;
    if (af != AF_INET) return -1;
    addr = inet_addr(src);
    if (addr == INADDR_NONE && strcmp(src, "255.255.255.255") != 0) return 0;
    *(unsigned long *)dst = addr;
    return 1;
}
#endif
#define inet_pton relay_inet_pton

#ifndef relay_inet_ntop_defined
#define relay_inet_ntop_defined
static __inline const char *relay_inet_ntop(int af, const void *src, char *dst, size_t sz) {
    const unsigned char *b = (const unsigned char *)src;
    if (af != AF_INET) return NULL;
    relay_snprintf(dst, sz, "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
    return dst;
}
#endif
#define inet_ntop relay_inet_ntop

#endif /* _WS2TCPIP_H_ */

#endif /* _MSC_VER < 1900 */
