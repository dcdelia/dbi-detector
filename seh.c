/*******************************************************************************
 *                                                                             *
 * sehdemo.cpp - Example SEH implementation for use with MinGW GCC (x86        *
 *               targets only).                                                *
 *                                                                             *
 * Copyright (c) 2011 Tom Bramer < tjb at postpro dot net >                    *
 *                                                                             *
 * Permission is hereby granted, free of charge, to any person                 *
 * obtaining a copy of this software and associated documentation              *
 * files (the "Software"), to deal in the Software without                     *
 * restriction, including without limitation the rights to use,                *
 * copy, modify, merge, publish, distribute, sublicense, and/or sell           *
 * copies of the Software, and to permit persons to whom the                   *
 * Software is furnished to do so, subject to the following                    *
 * conditions:                                                                 *
 *                                                                             *
 * The above copyright notice and this permission notice shall be              *
 * included in all copies or substantial portions of the Software.             *
 *                                                                             *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,             *
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES             *
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND                    *
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT                 *
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,                *
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING                *
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR               *
 * OTHER DEALINGS IN THE SOFTWARE.                                             *
 *                                                                             *
 *******************************************************************************/

#include <stdio.h>
#include <windows.h>


#include "seh.h"

      
// The main exception handler.
EXCEPTION_DISPOSITION __SEH_HANDLER::ExceptionRouter(PEXCEPTION_RECORD pRecord, 
        __SEH_EXCEPTION_REGISTRATION* pReg,
        PCONTEXT pContext,
        PEXCEPTION_RECORD pRecord2)
{
    // Retrieve the actual __SEH_HANDLER object from the registration, and call the 
    // specific exception handling function.  Everything could have been done from this
    // function alone, but I decided to use an instance method instead.
    return pReg->exthandler->ExceptionHandler(pRecord, pReg, pContext, pRecord2);
}

EXCEPTION_DISPOSITION __SEH_HANDLER::ExceptionHandler(PEXCEPTION_RECORD pRecord, 
        __SEH_EXCEPTION_REGISTRATION* pReg,
        PCONTEXT pContext,
        PEXCEPTION_RECORD pRecord2)
{
    // The objects pointed to by the pointers live on the stack, so a copy of them is required,
    // or they may get overwritten by the time we've hit the real exception handler code
    // back in the offending function. 
    CopyMemory(&excContext, pContext, sizeof(_CONTEXT));
    CopyMemory(&excRecord, pRecord, sizeof(_EXCEPTION_RECORD));

    // Jump back to the function where the exception actually occurred.  The 1 is the
    // return code that will be returned by set_jmp.
    longjmp(context, 1);
}
