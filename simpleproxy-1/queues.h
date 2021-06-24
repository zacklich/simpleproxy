

typedef struct dqueue_s {
    struct dqueue_s *next;
    struct dqueue_s *prev;
} dqueue_t;


static inline void dq_init(dqueue_t *q) 
{
   q->next = q; 
   q->prev = q;
}


static inline void dq_enqueue(dqueue_t *qb,dqueue_t *item)
{
    qb->prev->next = item;
    item->next = qb;
    item->prev = qb->prev;
    qb->prev = item;
}


static inline void dq_dequeue(dqueue_t *item)
{
    item->prev->next = item->next;
    item->next->prev = item->prev;
}


