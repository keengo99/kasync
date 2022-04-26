#include <stdarg.h>
#include <ucontext.h>
#include "sysdep.h"

/* Number of arguments that go in registers.  */
#define NREG_ARGS  4

#ifdef __cplusplus
extern "C" {
#endif
    extern void __startcontext();
#ifdef __cplusplus
}
#endif

/* Take a context previously prepared via getcontext() and set to
   call func() with the given int only args.  */
void makecontext(ucontext_t* ucp, void (*func) (void), int argc, ...)
{    
   

    unsigned long* funcstack;
    va_list vl;
    unsigned long* regptr;
    int reg;
    int misaligned;

    /* Start at the top of stack.  */
    funcstack = (unsigned long*)((char *)(ucp->uc_stack.ss_sp) + ucp->uc_stack.ss_size);

    /* Ensure the stack stays eight byte aligned.  */
    misaligned = ((unsigned long)funcstack & 4) != 0;

    if ((argc > NREG_ARGS) && (argc & 1) != 0)
        misaligned = !misaligned;

    if (misaligned)
        funcstack -= 1;

    va_start(vl, argc);

    /* Reserve space for the on-stack arguments.  */
    if (argc > NREG_ARGS)
        funcstack -= (argc - NREG_ARGS);

    ucp->uc_mcontext.arm_sp = (unsigned long)funcstack;
    ucp->uc_mcontext.arm_pc = (unsigned long)func;

    /* Exit to startcontext() with the next context in R4 */
    ucp->uc_mcontext.arm_r4 = (unsigned long)ucp->uc_link;
    ucp->uc_mcontext.arm_lr = (unsigned long)__startcontext;

    /* The first four arguments go into registers.  */
    regptr = &(ucp->uc_mcontext.arm_r0);

    for (reg = 0; (reg < argc) && (reg < NREG_ARGS); reg++)
        *regptr++ = va_arg(vl, unsigned long);

    /* And the remainder on the stack.  */
    for (; reg < argc; reg++)
        *funcstack++ = va_arg(vl, unsigned long);

    va_end(vl);
}