#define SP_ALIGN_SIZE       15

#define SP_ALIGN_MASK	   ~15

/* Size of an X regiser in bytes. */
#define SZREG                8

/* Size of a V register in bytes. */
#define SZVREG              16

/* Number of integer parameter passing registers. */
#define NUMXREGARGS          8

/* Number of FP parameter passing registers. */
#define NUMDREGARGS          8

/* Size of named integer argument in bytes when passed on the
   stack.  */
#define SIZEOF_NAMED_INT     4

   /* Size of an anonymous integer argument in bytes when passed on the
	  stack.  */
#define SIZEOF_ANONYMOUS_INT 8

#define oX21 (oX0 + 21*8)
#define oFP  (oX0 + 29*8)
#define oLR  (oX0 + 30*8)