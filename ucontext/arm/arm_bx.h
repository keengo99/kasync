#ifndef _ARM_BX_H
#define _ARM_BX_H

#if __ARM_ARCH > 4 || defined (__ARM_ARCH_4T__)
# define ARCH_HAS_BX
#endif

#if defined(ARCH_HAS_BX)
# define BX(reg)	bx reg
# define BXC(cond, reg)	bx##cond reg
#else
# define BX(reg)	mov pc, reg
# define BXC(cond, reg)	mov##cond pc, reg
#endif

#endif /* _ARM_BX_H */