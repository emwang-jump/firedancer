#ifndef HEADER_fd_src_disco_events_fd_event_client_h
#define HEADER_fd_src_disco_events_fd_event_client_h

#include "fd_event.h"
#include "fd_circq.h"
#include "../../disco/keyguard/fd_keyguard_client.h"

struct fd_event_client;
typedef struct fd_event_client fd_event_client_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_event_client_align( void );

FD_FN_CONST ulong
fd_event_client_footprint( void );

void *
fd_event_client_new( void *                 shmem,
                     fd_keyguard_client_t * keyguard_client,
                     fd_rng_t *             rng,
                     fd_circq_t *           circq,
                     int                    so_sndbuf,
                     char const *           endpoint,
                     uchar const *          identity_pubkey,
                     char const *           client_version,
                     ulong                  instance_id,
                     ulong                  boot_id,
                     ulong                  machine_id );

fd_event_client_t *
fd_event_client_join( void * shec );

void
fd_event_client_init_genesis_hash( fd_event_client_t * client,
                                   uchar const *       genesis_hash );

void
fd_event_client_init_shred_version( fd_event_client_t * client,
                                    ushort              shred_version );

void
fd_event_client_set_identity( fd_event_client_t * client,
                              uchar const *       identity_pubkey );

void
fd_event_client_poll( fd_event_client_t * client,
                      int *               charge_busy );

void
fd_event_client_append( fd_event_client_t * client,
                        fd_event_t const *  event );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_events_fd_event_client_h */
