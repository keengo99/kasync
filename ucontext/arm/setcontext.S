#include "sysdep.h"

#include "ucontext_i.h"

	.syntax unified
	.text

/* int setcontext (const ucontext_t *ucp) */

ENTRY(setcontext)
	mov	r4, r0

#if (defined __VFP_FP__) && !defined (__ANDROID__)
	/* Following instruction is vldmia r0!, {d8-d15}.  */
	ldc     p11, cr8, [r0], #64
	/* Restore the floating-point status register.  */
	ldr     r1, [r0], #4
	/* Following instruction is fmxr fpscr, r1.  */
	mcr     p10, 7, r1, cr1, cr0, 0
#endif

#ifdef __IWMMXT__
	/* Restore the call-preserved iWMMXt registers.  */
	/* Following instructions are wldrd wr10, [r0], #8 (etc.)  */
	ldcl    p1, cr10, [r0], #8
	ldcl    p1, cr11, [r0], #8
	ldcl    p1, cr12, [r0], #8
	ldcl    p1, cr13, [r0], #8
	ldcl    p1, cr14, [r0], #8
	ldcl    p1, cr15, [r0], #8
#endif

	/* Now bring back the signal status.  */
	mov	r0, #SIG_SETMASK
	add	r1, r4, #UCONTEXT_SIGMASK
	mov	r2, #0
	bl	PLTJMP(sigprocmask)

        /* Loading r0-r3 makes makecontext easier.  */
        add     r14, r4, #MCONTEXT_ARM_R0
        ldmia   r14, {r0-r11}
        ldr     r13, [r14, #(MCONTEXT_ARM_SP - MCONTEXT_ARM_R0)]
        add     r14, r14, #(MCONTEXT_ARM_LR - MCONTEXT_ARM_R0)
        ldmia   r14, {r14, pc}

END(setcontext)
// weak_alias(__setcontext, setcontext)

	/* Called when a makecontext() context returns.  Start the
	   context in R4 or fall through to exit().  */
ENTRY(__startcontext)
        movs    r0, r4
        bne     PLTJMP(setcontext)

        @ New context was 0 - exit
        b       PLTJMP(_exit)
END(__startcontext)
