// obtained from https://github.com/vitasdk/newlib/blob/vita/newlib/libc/sys/vita/vitaerror.h

/*

Copyright (C) 2017, David "Davee" Morgan
Copyright (C) 2018, Sunguk Lee

Permission is hereby granted, free of charge, to any person obtaining a
copy of this software and associated documentation files (the "Software"),
to deal in the Software without restriction, including without limitation
the rights to use, copy, modify, merge, publish, distribute, sublicense,
and/or sell copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.

*/

#ifndef _VITAERROR_H_
#define _VITAERROR_H_

#define SCE_ERRNO_MASK 0xFF
#define SCE_ERRNO_NONE 0x80010000
typedef enum
{
    ERROR_GENERIC,
    ERROR_SOCKET
} ErrorType;

int __vita_scenet_errno_to_errno(int sce_errno);
int __vita_sce_errno_to_errno(int sce_errno, int type);
int __vita_make_sce_errno(int posix_errno);

#endif // _VITAERROR_H_
