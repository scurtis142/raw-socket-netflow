#ifndef NETFLOW_TABLE_H
#define NETFLOW_TABLE_H

#define TABLE_INITIAL_SIZE 1024

typedef struct netflow_table_key {
    uint8_t proto;
    uint32_t ip_src;                                /**< saved in network order */
    uint32_t ip_dst;                                /**< saved in network order */
    uint16_t port_src;                              /**< saved in network order */
    uint16_t port_dst;                              /**< saved in network order */
} netflow_key_t;

typedef struct netflow_table_value {
   uint16_t bytes;
   uint16_t packets;
} netflow_value_t;

typedef struct netflow_hashBucket {
    uint8_t proto;
    uint32_t ip_src;                                /**< saved in network order */
    uint32_t ip_dst;                                /**< saved in network order */
    uint16_t port_src;                              /**< saved in network order */
    uint16_t port_dst;                              /**< saved in network order */

    uint64_t bytesSent;
    uint64_t pktSent;                               /**< saved in host order */

    struct netflow_hashBucket *next;
} hashBucket_t;


struct netflow_table {
   uint32_t n_entries;
   hashBucket_t **array;
};

/* Functions */
int get_netflow_k_v (const char *_p, int len, netflow_key_t *key, netflow_value_t *value);
struct netflow_table* netflow_table_init (void);
void netflow_table_insert (struct netflow_table *table, netflow_key_t *key, netflow_value_t *value);
/* void netflow_table_free (struct netflow_table *table); */
/* void netflow_table_print (struct netflow_table *table); */
void netflow_table_print_stats (struct netflow_table *table);

#endif
