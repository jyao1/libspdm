/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

/** @file
  Root include file of C runtime library to support building the third-party
  cryptographic library.
**/

#ifndef __CRT_LIB_SUPPORT_H__
#define __CRT_LIB_SUPPORT_H__

#include <base.h>
#include <library/memlib.h>
#include <library/debuglib.h>

struct tm *gmtime_r(const time_t *timep, struct tm *result);
char *strptime(const char *buf,const char *format, struct tm *tm);
time_t  timegm(struct tm* brokentime);

#endif
