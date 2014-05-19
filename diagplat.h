/* Copyright 2012, 2014 Jeff Trawick, http://emptyhammock.com/
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef DIAGPLAT_H
#define DIAGPLAT_H

#define DIAG_PLATFORM_WINDOWS          0
#define DIAG_PLATFORM_LINUX            0
#define DIAG_PLATFORM_FREEBSD          0
#define DIAG_PLATFORM_MACOSX           0
#define DIAG_PLATFORM_SOLARIS          0

#if defined(WIN32) || defined(_MSC_VER)
#undef DIAG_PLATFORM_WINDOWS
#define DIAG_PLATFORM_WINDOWS          1
#endif

#if defined(__linux__)
#undef DIAG_PLATFORM_LINUX
#define DIAG_PLATFORM_LINUX            1
#endif

#if defined(__FreeBSD__) || defined(__DragonFly__)
#undef DIAG_PLATFORM_FREEBSD
#define DIAG_PLATFORM_FREEBSD          1
#endif

#if defined(__MACH__)
#undef DIAG_PLATFORM_MACOSX
#define DIAG_PLATFORM_MACOSX           1
#endif

#if defined(SOLARIS) || defined(SOLARIS2)
#undef DIAG_PLATFORM_SOLARIS
#define DIAG_PLATFORM_SOLARIS          1
#endif

#if DIAG_PLATFORM_WINDOWS
#define DIAG_PLATFORM_UNIX             0
#else
#define DIAG_PLATFORM_UNIX             1
#endif

#if DIAG_PLATFORM_LINUX || DIAG_PLATFORM_FREEBSD || DIAG_PLATFORM_MACOSX
#define DIAG_HAVE_EXECINFO_BACKTRACE   1
#else
#define DIAG_HAVE_EXECINFO_BACKTRACE   0
#endif

#endif /* DIAGPLAT_H */
