#ifndef MSOCKET_LIST_H
#define MSOCKET_LIST_H
#include "kfeature.h"
#ifndef _WIN32
#include <stddef.h>
#endif
KBEGIN_DECLS
typedef struct kgl_forward_list_s kgl_forward_list;
struct kgl_forward_list_s
{
    kgl_forward_list* next;
};
INLINE void kforward_list_init(kgl_forward_list* list) {
    list->next = list;
}
INLINE bool kforward_list_empty(kgl_forward_list* list) {
    return list->next == list;
}
INLINE void kforward_list_append(kgl_forward_list* list, kgl_forward_list *item) {
    item->next = list->next;
    list->next = item;
}
INLINE bool kfoward_list_remove(kgl_forward_list* list, kgl_forward_list* item) {
    kgl_forward_list* pos = list;
    while (pos->next != list) {
        if (pos->next == item) {
            pos->next = item->next;
            return true;
        }
        pos = pos->next;
    }
    return false;
}

typedef struct kgl_list_s kgl_list;
struct kgl_list_s {
	kgl_list  *prev;
	kgl_list  *next;
};
#define klist_init(list) do {\
        (list)->next = (list);\
        (list)->prev = (list);\
} while(0)
#define klist_empty(list) ((list)->next == list)
//x will insert before list
#define klist_insert(list,  x)   do {\
    (x)->prev = (list)->prev;\
    (x)->prev->next = x; \
    (x)->next = (list); \
    (list)->prev = x;\
} while (0)

#define klist_append(list,  new_link) klist_insert(list,new_link)
#define klist_insert_tail klist_insert

#define klist_remove(link) do {\
        (link)->prev->next = (link)->next;\
        (link)->next->prev = (link)->prev;\
} while(0)
#define klist_head(list) (list)->next;
#define klist_end(list)  (list)->prev;
#define klist_foreach(pos, list)                  \
        for (pos = (list)->next;                  \
		pos != (list);                      \
		pos = pos->next)
#define klist_rforeach(pos, list)                 \
        for (pos = (list)->prev;                  \
		pos != (list);                      \
		pos = pos->prev)
#define kgl_list_data(list, type, sub_type) (type *) ((unsigned char *)list - offsetof(type, sub_type))
KEND_DECLS
#endif
