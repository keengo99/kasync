#ifndef _AARCH64_SYSDEP_H
#define _AARCH64_SYSDEP_H

#ifndef C_LABEL

/* Define a macro we can use to construct the asm name for a C symbol.  */
# define C_LABEL(name)  name##:

#endif

#ifdef __ASSEMBLER__
/* Mark the end of function named SYM.  This is used on some platforms
   to generate correct debugging information.  */
# ifndef END
#  define END(sym)
# endif

# ifndef JUMPTARGET
#  define JUMPTARGET(sym) sym
# endif
#endif

   /* Makros to generate eh_frame unwind information.  */
#ifdef __ASSEMBLER__
# define cfi_startproc      .cfi_startproc
# define cfi_endproc      .cfi_endproc
# define cfi_def_cfa(reg, off)    .cfi_def_cfa reg, off
# define cfi_def_cfa_register(reg)  .cfi_def_cfa_register reg
# define cfi_def_cfa_offset(off)  .cfi_def_cfa_offset off
# define cfi_adjust_cfa_offset(off) .cfi_adjust_cfa_offset off
# define cfi_offset(reg, off)   .cfi_offset reg, off
# define cfi_rel_offset(reg, off) .cfi_rel_offset reg, off
# define cfi_register(r1, r2)   .cfi_register r1, r2
# define cfi_return_column(reg) .cfi_return_column reg
# define cfi_restore(reg)   .cfi_restore reg
# define cfi_same_value(reg)    .cfi_same_value reg
# define cfi_undefined(reg)   .cfi_undefined reg
# define cfi_remember_state   .cfi_remember_state
# define cfi_restore_state    .cfi_restore_state
# define cfi_window_save    .cfi_window_save
# define cfi_personality(enc, exp)  .cfi_personality enc, exp
# define cfi_lsda(enc, exp)   .cfi_lsda enc, exp

#else /* ! ASSEMBLER */

# define CFI_STRINGIFY(Name) CFI_STRINGIFY2 (Name)
# define CFI_STRINGIFY2(Name) #Name
# define CFI_STARTPROC  ".cfi_startproc"
# define CFI_ENDPROC  ".cfi_endproc"
# define CFI_DEF_CFA(reg, off)  \
   ".cfi_def_cfa " CFI_STRINGIFY(reg) "," CFI_STRINGIFY(off)
# define CFI_DEF_CFA_REGISTER(reg) \
   ".cfi_def_cfa_register " CFI_STRINGIFY(reg)
# define CFI_DEF_CFA_OFFSET(off) \
   ".cfi_def_cfa_offset " CFI_STRINGIFY(off)
# define CFI_ADJUST_CFA_OFFSET(off) \
   ".cfi_adjust_cfa_offset " CFI_STRINGIFY(off)
# define CFI_OFFSET(reg, off) \
   ".cfi_offset " CFI_STRINGIFY(reg) "," CFI_STRINGIFY(off)
# define CFI_REL_OFFSET(reg, off) \
   ".cfi_rel_offset " CFI_STRINGIFY(reg) "," CFI_STRINGIFY(off)
# define CFI_REGISTER(r1, r2) \
   ".cfi_register " CFI_STRINGIFY(r1) "," CFI_STRINGIFY(r2)
# define CFI_RETURN_COLUMN(reg) \
   ".cfi_return_column " CFI_STRINGIFY(reg)
# define CFI_RESTORE(reg) \
   ".cfi_restore " CFI_STRINGIFY(reg)
# define CFI_UNDEFINED(reg) \
   ".cfi_undefined " CFI_STRINGIFY(reg)
# define CFI_REMEMBER_STATE \
   ".cfi_remember_state"
# define CFI_RESTORE_STATE \
   ".cfi_restore_state"
# define CFI_WINDOW_SAVE \
   ".cfi_window_save"
# define CFI_PERSONALITY(enc, exp) \
   ".cfi_personality " CFI_STRINGIFY(enc) "," CFI_STRINGIFY(exp)
# define CFI_LSDA(enc, exp) \
   ".cfi_lsda " CFI_STRINGIFY(enc) "," CFI_STRINGIFY(exp)
#endif



#define HAVE_SYSCALLS

/* Note that using a `PASTE' macro loses.  */
#define SYSCALL__(name, args) PSEUDO (__##name, name, args)
#define SYSCALL(name, args) PSEUDO (name, name, args)

/* Machine-dependent sysdep.h files are expected to define the macro
   PSEUDO (function_name, syscall_name) to emit assembly code to define the
   C-callable function FUNCTION_NAME to do system call SYSCALL_NAME.
   r0 and r1 are the system call outputs.  MOVE(x, y) should be defined as
   an instruction such that "MOVE(r1, r0)" works.  ret should be defined
   as the return instruction.  */

#define SYS_ify(syscall_name) SYS_##syscall_name

   /* Terminate a system call named SYM.  This is used on some platforms
	  to generate correct debugging information.  */
#ifndef PSEUDO_END
#define PSEUDO_END(sym)
#endif
#ifndef PSEUDO_END_NOERRNO
#define PSEUDO_END_NOERRNO(sym) PSEUDO_END(sym)
#endif
#ifndef PSEUDO_END_ERRVAL
#define PSEUDO_END_ERRVAL(sym)  PSEUDO_END(sym)
#endif

	  /* Wrappers around system calls should normally inline the system call code.
		 But sometimes it is not possible or implemented and we use this code.  */
#define INLINE_SYSCALL(name, nr, args...) __syscall_##name (args)




#ifdef  __ASSEMBLER__

		 /* Syntactic details of assembler.  */

#define ASM_SIZE_DIRECTIVE(name) .size name,.-name



   /* If compiled for profiling, call `mcount' at the start of each function.  */
#ifdef  PROF
# define CALL_MCOUNT            \
  str x30, [sp, #-16]!;       \
  bl  mcount;           \
  ldr x30, [sp], #16  ;
#else
# define CALL_MCOUNT    /* Do nothing.  */
#endif

/* Local label name for asm code.  */
#ifndef L
# define L(name)         .L##name
#endif



/* Load or store to/from a got-relative EXPR into/from R, using T.  */
#define LDST_GLOBAL(OP, R, T, EXPR)     \
  adrp  T, :got:EXPR;   \
  ldr T, [T, #:got_lo12:EXPR];\
  OP  R, [T];

/* Since C identifiers are not normally prefixed with an underscore
   on this system, the asm identifier `syscall_error' intrudes on the
   C name space.  Make sure we use an innocuous name.  */
#define syscall_error __syscall_error
#define mcount    _mcount

#endif  /* __ASSEMBLER__ */


//#include <features.h>

   /* Provide the common name to allow more code reuse.  */
#define __NR__llseek __NR_llseek

#if __WORDSIZE == 64
/* By defining the older names, glibc will build syscall wrappers for
   both pread and pread64; sysdeps/unix/sysv/linux/wordsize-64/pread64.c
   will suppress generating any separate code for pread64.c.  */
#define __NR_pread __NR_pread64
#define __NR_pwrite __NR_pwrite64
#endif

   /* Provide a dummy argument that can be used to force register
	  alignment for register pairs if required by the syscall ABI.  */
#ifdef __ASSUME_ALIGNED_REGISTER_PAIRS
#define __ALIGNMENT_ARG 0,
#define __ALIGNMENT_COUNT(a,b) b
#else
#define __ALIGNMENT_ARG
#define __ALIGNMENT_COUNT(a,b) a
#endif


#ifndef C_SYMBOL_NAME
# define C_SYMBOL_NAME(name) name
#endif



#ifdef __LP64__
# define AARCH64_R(NAME)	R_AARCH64_ ## NAME
# define PTR_REG(n)		x##n
# define PTR_LOG_SIZE		3
# define PTR_ARG(n)
# define SIZE_ARG(n)
#else
# define AARCH64_R(NAME)	R_AARCH64_P32_ ## NAME
# define PTR_REG(n)		w##n
# define PTR_LOG_SIZE		2
# define PTR_ARG(n)		mov     w##n, w##n
# define SIZE_ARG(n)		mov     w##n, w##n
#endif

#define PTR_SIZE	(1<<PTR_LOG_SIZE)

#ifndef __ASSEMBLER__
	  /* Strip pointer authentication code from pointer p.  */
static inline void*
strip_pac(void* p)
{
	register void* ra asm("x30") = (p);
	asm("hint 7 // xpaclri" : "+r"(ra));
	return ra;
}

/* This is needed when glibc is built with -mbranch-protection=pac-ret
   with a gcc that is affected by PR target/94891.  */
# if HAVE_AARCH64_PAC_RET
#  undef RETURN_ADDRESS
#  define RETURN_ADDRESS(n) strip_pac (__builtin_return_address (n))
# endif
#endif

#ifdef	__ASSEMBLER__

   /* Syntactic details of assembler.  */

#define ASM_SIZE_DIRECTIVE(name) .size name,.-name

/* Branch Target Identitication support.  */
#if HAVE_AARCH64_BTI
# define BTI_C		hint	34
# define BTI_J		hint	36
#else
# define BTI_C		nop
# define BTI_J		nop
#endif

/* Return address signing support (pac-ret).  */
#define PACIASP		hint	25
#define AUTIASP		hint	29

/* GNU_PROPERTY_AARCH64_* macros from elf.h for use in asm code.  */
#define FEATURE_1_AND 0xc0000000
#define FEATURE_1_BTI 1
#define FEATURE_1_PAC 2

/* Add a NT_GNU_PROPERTY_TYPE_0 note.  */
#define GNU_PROPERTY(type, value)	\
  .section .note.gnu.property, "a";	\
  .p2align 3;				\
  .word 4;				\
  .word 16;				\
  .word 5;				\
  .asciz "GNU";				\
  .word type;				\
  .word 4;				\
  .word value;				\
  .word 0;				\
  .text

/* Add GNU property note with the supported features to all asm code
   where sysdep.h is included.  */
#if HAVE_AARCH64_BTI && HAVE_AARCH64_PAC_RET
GNU_PROPERTY(FEATURE_1_AND, FEATURE_1_BTI | FEATURE_1_PAC)
#elif HAVE_AARCH64_BTI
GNU_PROPERTY(FEATURE_1_AND, FEATURE_1_BTI)
#endif

/* Define an entry point visible from C.  */
#define ENTRY(name)						\
  .globl C_SYMBOL_NAME(name);					\
  .type C_SYMBOL_NAME(name),%function;				\
  .p2align 6;							\
  C_LABEL(name)							\
  cfi_startproc;						\
  BTI_C;							\
  CALL_MCOUNT

/* Define an entry point visible from C.  */
#define ENTRY_ALIGN(name, align)				\
  .globl C_SYMBOL_NAME(name);					\
  .type C_SYMBOL_NAME(name),%function;				\
  .p2align align;						\
  C_LABEL(name)							\
  cfi_startproc;						\
  BTI_C;							\
  CALL_MCOUNT

/* Define an entry point visible from C with a specified alignment and
   pre-padding with NOPs.  This can be used to ensure that a critical
   loop within a function is cache line aligned.  Note this version
   does not adjust the padding if CALL_MCOUNT is defined. */

#define ENTRY_ALIGN_AND_PAD(name, align, padding)		\
  .globl C_SYMBOL_NAME(name);					\
  .type C_SYMBOL_NAME(name),%function;				\
  .p2align align;						\
  .rep padding - 1; /* -1 for bti c.  */			\
  nop;								\
  .endr;							\
  C_LABEL(name)							\
  cfi_startproc;						\
  BTI_C;							\
  CALL_MCOUNT

#undef	END
#define END(name)						\
  cfi_endproc;							\
  ASM_SIZE_DIRECTIVE(name)

   /* If compiled for profiling, call `mcount' at the start of each function.  */
#ifdef	PROF
# define CALL_MCOUNT						\
	str	x30, [sp, #-80]!;				\
	cfi_adjust_cfa_offset (80);				\
	cfi_rel_offset (x30, 0);				\
	stp	x0, x1, [sp, #16];				\
	cfi_rel_offset (x0, 16);				\
	cfi_rel_offset (x1, 24);				\
	stp	x2, x3, [sp, #32];				\
	cfi_rel_offset (x2, 32);				\
	cfi_rel_offset (x3, 40);				\
	stp	x4, x5, [sp, #48];				\
	cfi_rel_offset (x4, 48);				\
	cfi_rel_offset (x5, 56);				\
	stp	x6, x7, [sp, #64];				\
	cfi_rel_offset (x6, 64);				\
	cfi_rel_offset (x7, 72);				\
	mov	x0, x30;					\
	bl	mcount;						\
	ldp	x0, x1, [sp, #16];				\
	cfi_restore (x0);					\
	cfi_restore (x1);					\
	ldp	x2, x3, [sp, #32];				\
	cfi_restore (x2);					\
	cfi_restore (x3);					\
	ldp	x4, x5, [sp, #48];				\
	cfi_restore (x4);					\
	cfi_restore (x5);					\
	ldp	x6, x7, [sp, #64];				\
	cfi_restore (x6);					\
	cfi_restore (x7);					\
	ldr	x30, [sp], #80;					\
	cfi_adjust_cfa_offset (-80);				\
	cfi_restore (x30);
#else
# define CALL_MCOUNT		/* Do nothing.  */
#endif

/* Local label name for asm code.  */
#ifndef L
# define L(name)         .L##name
#endif



	  /* Load an immediate into R.
		 Note R is a register number and not a register name.  */
#ifdef __LP64__
# define MOVL(R, NAME)					\
	movz	PTR_REG (R), #:abs_g3:NAME;		\
	movk	PTR_REG (R), #:abs_g2_nc:NAME;		\
	movk	PTR_REG (R), #:abs_g1_nc:NAME;		\
	movk	PTR_REG (R), #:abs_g0_nc:NAME;
#else
# define MOVL(R, NAME)					\
	movz	PTR_REG (R), #:abs_g1:NAME;		\
	movk	PTR_REG (R), #:abs_g0_nc:NAME;
#endif

		 /* Since C identifiers are not normally prefixed with an underscore
			on this system, the asm identifier `syscall_error' intrudes on the
			C name space.  Make sure we use an innocuous name.  */
#define syscall_error	__syscall_error
#define mcount		_mcount

#endif	/* __ASSEMBLER__ */
#endif  /* _AARCH64_SYSDEP_H */