
//          Copyright Oliver Kowalke 2009.
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#ifndef BOOST_CONTEXT_DETAIL_FCONTEXT_H
#define BOOST_CONTEXT_DETAIL_FCONTEXT_H
#include <stddef.h>
#ifdef  __cplusplus
extern "C" {
#endif
#if (defined(i386) || defined(__i386__) || defined(__i386) \
     || defined(__i486__) || defined(__i586__) || defined(__i686__) \
     || defined(__X86__) || defined(_X86_) || defined(__THW_INTEL__) \
     || defined(__I86__) || defined(__INTEL__) || defined(__IA32__) \
     || defined(_M_IX86) || defined(_I86_)) && defined(_WIN32)
# define BOOST_CONTEXT_CALLDECL __cdecl
#else
# define BOOST_CONTEXT_CALLDECL
#endif
typedef void* fcontext_t;

typedef struct {
    fcontext_t  fctx;
    void* data;
} transfer_t;
transfer_t BOOST_CONTEXT_CALLDECL jump_fcontext(fcontext_t const to, void* vp);
fcontext_t BOOST_CONTEXT_CALLDECL make_fcontext(void* sp, size_t size, void (*fn)(transfer_t));
transfer_t BOOST_CONTEXT_CALLDECL ontop_fcontext(fcontext_t const to, void* vp, transfer_t(*fn)(transfer_t));

#ifdef  __cplusplus
}
#endif

#endif // BOOST_CONTEXT_DETAIL_FCONTEXT_H

