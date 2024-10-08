#include "kmalloc.h"
#include <string.h>
#include "katom.h"
unsigned kgl_pagesize;
size_t kgl_aio_align_size = 512;

#ifndef KGL_ALIGNMENT
#define KGL_ALIGNMENT   sizeof(unsigned long)    /* platform word */
#endif

static void* kgl_palloc_block(kgl_pool_t* pool, size_t size) {
	char* m;
	size_t       psize;
	kgl_pool_t* p, * n;

	psize = (size_t)(pool->d.end - (char*)pool);

	m = (char*)kgl_memalign(KGL_POOL_ALIGNMENT, psize);
	if (m == NULL) {
		return NULL;
	}

	n = (kgl_pool_t*)m;

	n->d.end = m + psize;
	n->d.next = NULL;
	n->d.failed = 0;

	m += sizeof(kgl_pool_data_t);
	m = (char*)kgl_align_ptr(m, KGL_ALIGNMENT);
	n->d.last = m + size;

	for (p = pool->current; p->d.next; p = p->d.next) {
		if (p->d.failed++ > 4) {
			pool->current = p->d.next;
		}
	}

	p->d.next = n;

	return m;
}

static INLINE void* kgl_palloc_small(kgl_pool_t* pool, size_t size, size_t align) {
	char* m;
	kgl_pool_t* p;

	p = pool->current;

	do {
		m = p->d.last;

		if (align) {
			m = (char*)kgl_align_ptr(m, KGL_ALIGNMENT);
		}

		if ((size_t)(p->d.end - m) >= size) {
			p->d.last = m + size;

			return m;
		}

		p = p->d.next;

	} while (p);

	return kgl_palloc_block(pool, size);
}


static void* kgl_palloc_large(kgl_pool_t* pool, size_t size) {
	void* p;
	uintptr_t         n;
	kgl_pool_large_t* large;

	p = (char*)malloc(size);
	if (p == NULL) {
		return NULL;
	}

	n = 0;

	for (large = pool->large; large; large = large->next) {
		if (large->alloc == NULL) {
			large->alloc = p;
			return p;
		}

		if (n++ > 3) {
			break;
		}
	}
	large = (kgl_pool_large_t*)kgl_palloc_small(pool, sizeof(kgl_pool_large_t), 1);
	if (large == NULL) {
		free(p);
		return NULL;
	}

	large->alloc = p;
	large->next = pool->large;
	pool->large = large;

	return p;
}


kgl_pool_t* kgl_create_pool(size_t size) {
	kgl_pool_t* p;

	p = (kgl_pool_t*)kgl_memalign(KGL_POOL_ALIGNMENT, size);
	if (p == NULL) {
		return NULL;
	}
	p->cleanup = NULL;

	p->d.last = (char*)p + sizeof(kgl_pool_t);
	p->d.end = (char*)p + size;
	p->d.next = NULL;
	p->d.failed = 0;

	size = size - sizeof(kgl_pool_t);
	p->max = (size < KGL_MAX_ALLOC_FROM_POOL) ? size : KGL_MAX_ALLOC_FROM_POOL;

	p->current = p;
	p->large = NULL;
	return p;
}
void kgl_destroy_pool(kgl_pool_t* pool) {
	kgl_pool_t* p, * n;
	kgl_pool_large_t* l;
	kgl_cleanup_t* c;
	for (c = pool->cleanup; c; c = c->next) {
		if (c->handler) {
			c->handler(c->data);
		}
	}
	for (l = pool->large; l; l = l->next) {

		if (l->alloc) {
			free(l->alloc);
		}
	}

	for (p = pool, n = pool->d.next; /* void */; p = n, n = n->d.next) {
		kgl_align_free(p);
		if (n == NULL) {
			break;
		}
	}
}
void kgl_reset_pool(kgl_pool_t* pool) {
	kgl_pool_t* p;
	kgl_pool_large_t* l;
	kgl_cleanup_t* c;
	for (c = pool->cleanup; c; c = c->next) {
		if (c->handler) {
			c->handler(c->data);
		}
	}
	pool->cleanup = NULL;

	for (l = pool->large; l; l = l->next) {
		if (l->alloc) {
			free(l->alloc);
		}
	}
	for (p = pool; p; p = p->d.next) {
		p->d.last = (char*)p + sizeof(kgl_pool_t);
		p->d.failed = 0;
	}
	pool->current = pool;
	pool->large = NULL;
}
void* kgl_palloc(kgl_pool_t* pool, size_t size) {
#if !(KGL_DEBUG_PALLOC)
	if (size <= pool->max) {
		return kgl_palloc_small(pool, size, 1);
	}
#endif

	return kgl_palloc_large(pool, size);
}


void* kgl_pnalloc(kgl_pool_t* pool, size_t size) {
#if !(KGL_DEBUG_PALLOC)
	if (size <= pool->max) {
		return kgl_palloc_small(pool, size, 0);
	}
#endif
	return kgl_palloc_large(pool, size);
}
void* kgl_cleanup_get_data(kgl_cleanup_t* c) {
	return c->data;
}
void kgl_cleanup_set_data(kgl_cleanup_t* c, void* data) {
	c->data = data;
}
kgl_cleanup_t* kgl_cleanup_insert(kgl_pool_t* p, kgl_cleanup_f handler) {
	kgl_cleanup_t* c;
	for (c = p->cleanup; c != NULL; c = c->next) {
		if (c->handler == handler) {
			return c;
		}
	}
	return kgl_cleanup_add(p, handler, NULL);
}
kgl_cleanup_t* kgl_cleanup_add(kgl_pool_t* p, kgl_cleanup_f handler, void* data) {
	kgl_cleanup_t* c = (kgl_cleanup_t*)kgl_palloc(p, sizeof(kgl_cleanup_t));
	if (c == NULL) {
		return NULL;
	}
	c->data = data;
	c->handler = handler;
	c->next = p->cleanup;
	p->cleanup = c;
	return c;
}
bool kgl_pfree(kgl_pool_t* pool, void* p) {
	kgl_pool_large_t* l;

	for (l = pool->large; l; l = l->next) {
		if (p == l->alloc) {
			free(l->alloc);
			l->alloc = NULL;

			return true;
		}
	}

	return false;
}
kgl_array_t* kgl_array_create(kgl_pool_t* p, size_t n, size_t size) {
	kgl_array_t* a;

	a = (kgl_array_t*)kgl_palloc(p, sizeof(kgl_array_t));
	if (a == NULL) {
		return NULL;
	}

	if (!kgl_array_init(a, p, n, size)) {
		return NULL;
	}

	return a;
}

void kgl_array_destroy(kgl_array_t* a) {
	kgl_pool_t* p;

	p = a->pool;

	if ((char*)a->elts + a->size * a->nalloc == p->d.last) {
		p->d.last -= a->size * a->nalloc;
	}

	if ((char*)a + sizeof(kgl_array_t) == p->d.last) {
		p->d.last = (char*)a;
	}
}


void* kgl_array_push(kgl_array_t* a) {
	void* elt, * new_elt;
	size_t       size;
	kgl_pool_t* p;

	if (a->nelts == a->nalloc) {

		/* the array is full */

		size = a->size * a->nalloc;

		p = a->pool;

		if ((char*)a->elts + size == p->d.last
			&& p->d.last + a->size <= p->d.end) {
			/*
			* the array allocation is the last in the pool
			* and there is space for new allocation
			*/

			p->d.last += a->size;
			a->nalloc++;

		} else {
			/* allocate a new array */

			new_elt = kgl_palloc(p, 2 * size);
			if (new_elt == NULL) {
				return NULL;
			}

			kgl_memcpy(new_elt, a->elts, size);
			a->elts = new_elt;
			a->nalloc *= 2;
		}
	}

	elt = (char*)a->elts + a->size * a->nelts;
	a->nelts++;

	return elt;
}


void* kgl_array_push_n(kgl_array_t* a, size_t n) {
	void* elt, * new_elt;
	size_t       size;
	size_t   nalloc;
	kgl_pool_t* p;

	size = n * a->size;

	if (a->nelts + n > a->nalloc) {

		/* the array is full */

		p = a->pool;

		if ((char*)a->elts + a->size * a->nalloc == p->d.last
			&& p->d.last + size <= p->d.end) {
			/*
			* the array allocation is the last in the pool
			* and there is space for new allocation
			*/

			p->d.last += size;
			a->nalloc += n;

		} else {
			/* allocate a new array */

			nalloc = 2 * ((n >= a->nalloc) ? n : a->nalloc);

			new_elt = kgl_palloc(p, nalloc * a->size);
			if (new_elt == NULL) {
				return NULL;
			}

			kgl_memcpy(new_elt, a->elts, a->nelts * a->size);
			a->elts = new_elt;
			a->nalloc = nalloc;
		}
	}

	elt = (u_char*)a->elts + a->size * a->nelts;
	a->nelts += n;

	return elt;
}
void* kgl_pmemalign(kgl_pool_t* pool, size_t size, size_t alignment) {
	void* p;
	kgl_pool_large_t* large;

	p = kgl_memalign(alignment, size);
	if (p == NULL) {
		return NULL;
	}
	large = (kgl_pool_large_t*)kgl_palloc_small(pool, sizeof(kgl_pool_large_t), 1);
	if (large == NULL) {
		kgl_align_free(p);
		return NULL;
	}

	large->alloc = p;
	large->next = pool->large;
	pool->large = large;

	return p;
}
