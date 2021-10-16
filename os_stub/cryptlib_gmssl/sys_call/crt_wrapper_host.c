/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
**/

/** @file
  C Run-Time Libraries (CRT) Wrapper Implementation.
**/

#include <stdio.h>

#include <base.h>
#include <library/debuglib.h>


struct tm *gmtime_r(const time_t *timep, struct tm *result)
{
  return NULL;
}

char *strptime(const char *buf,const char *format, struct tm *tm)
{
  return NULL;
}

time_t  timegm(struct tm* brokentime)
{
  return 0;
}
