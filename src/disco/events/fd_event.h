#ifndef HEADER_fd_src_disco_events_fd_event_h
#define HEADER_fd_src_disco_events_fd_event_h

#include "../../util/net/fd_net_headers.h"

enum fd_event_tag {
  FD_EVENT_TAG_SHRED = 0,
  FD_EVENT_TAG_TXN   = 1,
};

typedef enum fd_event_tag fd_event_tag_t;

enum fd_event_shred_protocol {
  FD_EVENT_SHRED_PROTOCOL_TURBINE = 0,
  FD_EVENT_SHRED_PROTOCOL_REPAIR  = 1,
};

typedef enum fd_event_shred_protocol fd_event_shred_protocol_t;

struct fd_event_shred {
  fd_ip4_port_t src;
  fd_event_shred_protocol_t protocol;

  ulong payload_off;
  ulong payload_len;
};

typedef struct fd_event_shred fd_event_shred_t;

enum fd_event_txn_protocol {
  FD_EVENT_TXN_PROTOCOL_QUIC   = 1,
  FD_EVENT_TXN_PROTOCOL_UDP    = 2,
  FD_EVENT_TXN_PROTOCOL_GOSSIP = 3,
  FD_EVENT_TXN_PROTOCOL_BUNDLE = 4,
  FD_EVENT_TXN_PROTOCOL_SEND   = 5,
};

typedef enum fd_event_txn_protocol fd_event_txn_protocol_t;

struct fd_event_txn {
  fd_ip4_port_t src;
  fd_event_txn_protocol_t protocol;

  ulong bundle_id;
  ulong bundle_txn_cnt;
  uchar commission;
  uchar commission_pubkey[ 32UL ];

  ulong payload_off;
  ulong payload_len;
};

typedef struct fd_event_txn fd_event_txn_t;

struct fd_event {
  fd_event_tag_t tag;
  long timestamp_nanos;
  union {
    fd_event_shred_t shred;
    fd_event_txn_t txn;
  } event;
};

typedef struct fd_event fd_event_t;

FD_PROTOTYPES_BEGIN

#define FD_EVENT_SERIALIZE_OVERFLOW (-1)
#define FD_EVENT_SERIALIZE_INVALID  (-2)

long
fd_event_serialize( fd_event_t const * event,
                    uchar *            buf,
                    ulong              buf_sz );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_events_fd_event_h */
