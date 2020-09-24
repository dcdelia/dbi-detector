#include <excpt.h>
#include <setjmp.h>

class __SEH_HANDLER;

typedef struct tag__SEH_EXCEPTION_REGISTRATION
{
    tag__SEH_EXCEPTION_REGISTRATION* prev;
    PEXCEPTION_HANDLER handler;
    __SEH_HANDLER* exthandler;
} __SEH_EXCEPTION_REGISTRATION;

class __SEH_HANDLER
{
    public:

        // This is the main exception handling function.  This is called
        // for each exception raised using this method.
        static EXCEPTION_DISPOSITION ExceptionRouter(PEXCEPTION_RECORD pRecord, 
                __SEH_EXCEPTION_REGISTRATION* pReg,
                PCONTEXT pContext,
                PEXCEPTION_RECORD pRecord2);

        // This is the exception handler for this specific instance.  This is called by the
        // ExceptionRouter class function.
        virtual EXCEPTION_DISPOSITION ExceptionHandler(PEXCEPTION_RECORD pRecord, 
                __SEH_EXCEPTION_REGISTRATION* pReg,
                PCONTEXT pContext,
                PEXCEPTION_RECORD pRecord2);

        // This is the context buffer used by setjmp.  This stores the context at a given point
        // in the program so that it can be resumed.
        jmp_buf context;

        // This is a copy of the EXCEPTION_RECORD structure passed to the exception handler.
        EXCEPTION_RECORD excRecord;
        // This is a copy of the CONTEXT structure passed to the exception handler.
        CONTEXT excContext;    
};

// Note the unmatched braces in these macros.  These are to allow one to use
// the same variable name more than once (new scope).
#define __seh_try                                                             \
{                                                                             \
    __SEH_EXCEPTION_REGISTRATION _lseh_er;                                    \
    __SEH_HANDLER _lseh_handler;                                              \
    \
    _lseh_er.handler =                                                        \
    reinterpret_cast<PEXCEPTION_HANDLER>(__SEH_HANDLER::ExceptionRouter); \
    _lseh_er.exthandler = &_lseh_handler;                                     \
    asm volatile ("movl %%fs:0, %0" : "=r" (_lseh_er.prev));                  \
    asm volatile ("movl %0, %%fs:0" : : "r" (&_lseh_er));                     \
    int _lseh_setjmp_res = setjmp(_lseh_handler.context);                     \
    while(true) {                                                             \
        if(_lseh_setjmp_res != 0) {                                           \
            break;                                                            \
        }                                                                     \


#define __seh_except(rec, ctx)                                                \
        break;                                                                \
    }                                                                         \
    PEXCEPTION_RECORD rec = &_lseh_handler.excRecord;                         \
    PCONTEXT ctx = &_lseh_handler.excContext;                                 \
                                                                              \
    asm volatile ("movl %0, %%fs:0" : : "r" (_lseh_er.prev));                 \
    if(_lseh_setjmp_res != 0)

#define __seh_end }
