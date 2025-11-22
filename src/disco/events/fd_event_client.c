#define _GNU_SOURCE
#include "fd_event_client.h"

#include "../../disco/keyguard/fd_keyguard.h"
#include "../../waltz/resolv/fd_netdb.h"
#include "../../waltz/http/fd_url.h"
#include "../../util/log/fd_log.h"

#include <netinet/tcp.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define STATE_DISCONNECTED               (0)
#define STATE_SENDING_HANDSHAKE          (1)
#define STATE_WAITING_FOR_CHALLENGE      (2)
#define STATE_SENDING_CHALLENGE_RESPONSE (3)
#define STATE_CONNECTED                  (4)

#define DISCONNECT_REASON_IDENTITY_CHANGED   (0)
#define DISCONNECT_REASON_CONNECT_FAILED     (1)
#define DISCONNECT_REASON_DNS_RESOLVE_FAILED (2)
#define DISCONNECT_REASON_TIMEOUT            (3)
#define DISCONNECT_REASON_SEND_FAILED        (4)
#define DISCONNECT_REASON_RECV_FAILED        (5)
#define DISCONNECT_REASON_PEER_CLOSED        (6)
#define DISCONNECT_REASON_INVALID_CURSOR     (7)

struct fd_event_client {
  char client_version[ 10UL ];
  uchar identity_pubkey[ 32UL ];

  int has_genesis_hash;
  uchar genesis_hash[ 32UL ];

  ushort has_shred_version;
  ushort shred_version;

  ulong instance_id;
  ulong boot_id;
  ulong machine_id;

  ulong consecutive_failure_count;

  int state;
  union {
    struct {
      long reconnect_deadline;
    } disconnected;

    struct {
      ulong handshake_bytes_sent;
      long  handshake_sent_deadline;
    } sending_handshake;

    struct {
      long challenge_deadline;
      ulong challenge_bytes_received;
      struct __attribute__((__packed__)) {
        char  magic[ 4UL ];
        uchar nonce[ 32UL ];
      } challenge;
    } waiting_for_challenge;

    struct {
      long  response_sent_deadline;
      ulong response_bytes_sent;
      uchar signature[ 64UL ];
    } sending_challenge_response;

    struct {
      struct {
        int   has_message;
        ulong message_bytes_sent;
        ulong message_bytes_len;
        uchar message_bytes[ 1UL<<24UL ];
      } tx;

      struct {
        long  cursor_deadline;
        ulong cursor_bytes_received;
        ulong cursor;
      } rx;
    } connected;
  };

  int so_sndbuf;
  int sockfd;

  char   server_fqdn[ 256 ]; /* cstr */
  ulong  server_fqdn_len;
  uint   server_ip4_addr;
  ushort server_tcp_port;

  fd_rng_t * rng;
  fd_circq_t * circq;
  fd_keyguard_client_t * keyguard_client;

  struct {
    ulong transport_fail_cnt;
    ulong transport_success_cnt;
  } metrics;
};

FD_FN_CONST ulong
fd_event_client_align( void ) {
  return alignof( fd_event_client_t );
}

FD_FN_CONST ulong
fd_event_client_footprint( void ) {
  return sizeof( fd_event_client_t );
}

static void
parse_url( fd_url_t *   url_,
           char const * url_str,
           ulong        url_str_len,
           ushort *     tcp_port ) {

  /* Parse URL */

  int url_err[1];
  fd_url_t * url = fd_url_parse_cstr( url_, url_str, url_str_len, url_err );
  if( FD_UNLIKELY( !url ) ) {
    switch( *url_err ) {
    scheme_err:
    case FD_URL_ERR_SCHEME:
      FD_LOG_ERR(( "Invalid [tiles.event.url] `%.*s`: must start with `http://`", (int)url_str_len, url_str ));
      break;
    case FD_URL_ERR_HOST_OVERSZ:
      FD_LOG_ERR(( "Invalid [tiles.event.url] `%.*s`: domain name is too long", (int)url_str_len, url_str ));
      break;
    default:
      FD_LOG_ERR(( "Invalid [tiles.event.url] `%.*s`", (int)url_str_len, url_str ));
      break;
    }
  }

  /* FIXME the URL scheme path technically shouldn't contain slashes */
  if( url->scheme_len==7UL && fd_memeq( url->scheme, "http://", 7UL ) ) {
  } else {
    goto scheme_err;
  }

  /* Parse port number */

  *tcp_port = 8787;
  if( url->port_len ) {
    if( FD_UNLIKELY( url->port_len > 5 ) ) {
    invalid_port:
      FD_LOG_ERR(( "Invalid [tiles.event.url] `%.*s`: invalid port number", (int)url_str_len, url_str ));
    }

    char port_cstr[6];
    fd_cstr_fini( fd_cstr_append_text( fd_cstr_init( port_cstr ), url->port, url->port_len ) );
    ulong port_no = fd_cstr_to_ulong( port_cstr );
    if( FD_UNLIKELY( !port_no || port_no>USHORT_MAX ) ) goto invalid_port;

    *tcp_port = (ushort)port_no;
  }

  /* Resolve domain */

  if( FD_UNLIKELY( url->host_len > 255 ) ) {
    FD_LOG_CRIT(( "Invalid url->host_len" )); /* unreachable */
  }
  char host_cstr[ 256 ];
  fd_cstr_fini( fd_cstr_append_text( fd_cstr_init( host_cstr ), url->host, url->host_len ) );
}

void *
fd_event_client_new( void *                 shmem,
                     fd_keyguard_client_t * keyguard_client,
                     fd_rng_t *             rng,
                     fd_circq_t *           circq,
                     int                    so_sndbuf,
                     char const *           _url,
                     uchar const *          identity_pubkey,
                     char const *           client_version,
                     ulong                  instance_id,
                     ulong                  boot_id,
                     ulong                  machine_id ) {
  fd_event_client_t * client = (fd_event_client_t *)shmem;

  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_event_client_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }
  fd_url_t url[1];
  parse_url(
      url,
      _url,
      strlen( _url ),
      &client->server_tcp_port );
  if( FD_UNLIKELY( url->host_len > 255 ) ) {
    FD_LOG_CRIT(( "Invalid url->host_len" )); /* unreachable */
  }
  fd_cstr_fini( fd_cstr_append_text( fd_cstr_init( client->server_fqdn ), url->host, url->host_len ) );
  client->server_fqdn_len = url->host_len;

  fd_memcpy( client->identity_pubkey, identity_pubkey, 32UL );
  strncpy( client->client_version, client_version, sizeof( client->client_version ) );
  client->client_version[ sizeof( client->client_version ) - 1UL ] = '\0';
  client->instance_id = instance_id;
  client->boot_id     = boot_id;
  client->machine_id  = machine_id;

  client->has_genesis_hash = 0;
  client->has_shred_version = 0;

  client->so_sndbuf = so_sndbuf;
  client->sockfd = -1;
  client->state = STATE_DISCONNECTED;
  client->disconnected.reconnect_deadline = 0L;

  client->consecutive_failure_count = 0UL;

  client->circq = circq;
  client->rng = rng;
  client->keyguard_client = keyguard_client;

  return (void *)client;
}

fd_event_client_t *
fd_event_client_join( void * shec ) {
  if( FD_UNLIKELY( !shec ) ) {
    FD_LOG_WARNING(( "NULL shec" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shec, fd_event_client_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shec" ));
    return NULL;
  }

  fd_event_client_t * client = (fd_event_client_t *)shec;

  return client;
}

void
fd_event_client_init_genesis_hash( fd_event_client_t * client,
                                   uchar const *       genesis_hash ) {
  fd_memcpy( client->genesis_hash, genesis_hash, 32UL );
  client->has_genesis_hash = 1;
}

void
fd_event_client_init_shred_version( fd_event_client_t * client,
                                    ushort              shred_version ) {
  client->shred_version = shred_version;
  client->has_shred_version = 1;
}

static void
backoff( fd_event_client_t * client ) {
  long now = fd_log_wallclock();
  ulong backoff_base = 1UL << fd_ulong_min( client->consecutive_failure_count, 7UL ); /* max 4 mins */
  ulong backoff_jitter = fd_rng_ulong_roll( client->rng, backoff_base );
  client->disconnected.reconnect_deadline = now + (long)( backoff_base + backoff_jitter )*(long)1e9;
  client->consecutive_failure_count++;
}

static void
disconnect( fd_event_client_t * client,
            int                 reason,
            int                 err,
            int                 _backoff ) {
  if( FD_LIKELY( -1!=client->sockfd ) ) {
    if( FD_UNLIKELY( -1==close( client->sockfd ) ) ) FD_LOG_ERR(( "close() failed (%d-%s)", errno, fd_io_strerror( errno ) ));
    client->sockfd = -1;
    client->state = STATE_DISCONNECTED;
    fd_circq_reset_cursor( client->circq );
  }

  switch( reason ) {
    case DISCONNECT_REASON_IDENTITY_CHANGED:
      FD_LOG_INFO(( "disconnected: identity changed" ));
      break;
    case DISCONNECT_REASON_CONNECT_FAILED:
      FD_LOG_WARNING(( "connecting to " FD_IP4_ADDR_FMT ":%u failed (%i-%s)", FD_IP4_ADDR_FMT_ARGS( client->server_ip4_addr ), client->server_tcp_port, errno, fd_io_strerror( errno ) ));
      client->metrics.transport_fail_cnt++;
      break;
    case DISCONNECT_REASON_DNS_RESOLVE_FAILED:
      FD_LOG_WARNING(( "connecting to `%.*s` failed (%d-%s)", (int)client->server_fqdn_len, client->server_fqdn, err, fd_gai_strerror( err ) ));
      client->metrics.transport_fail_cnt++;
      break;
    case DISCONNECT_REASON_TIMEOUT:
      FD_LOG_WARNING(( "disconnected: timeout" ));
      client->metrics.transport_fail_cnt++;
      break;
    case DISCONNECT_REASON_SEND_FAILED:
      FD_LOG_WARNING(( "disconnected: send failed (%d-%s)", err, fd_io_strerror( err ) ));
      client->metrics.transport_fail_cnt++;
      break;
    case DISCONNECT_REASON_RECV_FAILED:
      FD_LOG_WARNING(( "disconnected: recv failed (%d-%s)", err, fd_io_strerror( err ) ));
      client->metrics.transport_fail_cnt++;
      break;
    case DISCONNECT_REASON_PEER_CLOSED:
      FD_LOG_WARNING(( "disconnected: peer closed connection" ));
      client->metrics.transport_fail_cnt++;
      break;
    case DISCONNECT_REASON_INVALID_CURSOR:
      FD_LOG_WARNING(( "disconnected: invalid cursor" ));
      client->metrics.transport_fail_cnt++;
      break;
    default:
      FD_LOG_WARNING(( "disconnected: unknown reason %d", reason ));
      client->metrics.transport_fail_cnt++;
      break;
  }

  if( FD_LIKELY( _backoff ) ) backoff( client );
}

void
fd_event_client_set_identity( fd_event_client_t * client,
                              uchar const *       identity_pubkey ) {
  fd_memcpy( client->identity_pubkey, identity_pubkey, 32UL );
  disconnect( client, DISCONNECT_REASON_IDENTITY_CHANGED, 0, 0 );
}

static void
reconnect( fd_event_client_t * client,
           int *               charge_busy ) {
  FD_TEST( client->state==STATE_DISCONNECTED );

  long now = fd_log_wallclock();
  if( FD_UNLIKELY( now<client->disconnected.reconnect_deadline ) ) return;

  *charge_busy = 1;

  /* FIXME IPv6 support */
  fd_addrinfo_t hints = {0};
  hints.ai_family = AF_INET;
  fd_addrinfo_t * res = NULL;
  uchar scratch[ 4096 ];
  void * pscratch = scratch;
  int err = fd_getaddrinfo( client->server_fqdn, &hints, &res, &pscratch, sizeof(scratch) );
  if( FD_UNLIKELY( err ) ) {
    disconnect( client, DISCONNECT_REASON_DNS_RESOLVE_FAILED, err, 1 );
    return;
  }

  uint const ip4_addr = ((struct sockaddr_in *)res->ai_addr)->sin_addr.s_addr;
  client->server_ip4_addr = ip4_addr;

  client->sockfd = socket( AF_INET, SOCK_STREAM|SOCK_NONBLOCK, 0 );
  if( FD_UNLIKELY( -1==client->sockfd ) ) FD_LOG_ERR(( "socket() failed (%d-%s)", errno, fd_io_strerror( errno ) ));

  struct sockaddr_in addr;
  fd_memset( &addr, 0, sizeof( addr ) );
  addr.sin_family = AF_INET;
  addr.sin_port   = fd_ushort_bswap( client->server_tcp_port );
  addr.sin_addr.s_addr = ip4_addr;

  int tcp_nodelay = 1;
  if( FD_UNLIKELY( -1==setsockopt( client->sockfd, SOL_TCP, TCP_NODELAY, &tcp_nodelay, sizeof(int) ) ) ) FD_LOG_ERR(( "setsockopt failed (%d-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( -1==setsockopt( client->sockfd, SOL_SOCKET, SO_SNDBUF, &client->so_sndbuf, sizeof(int) ) ) ) FD_LOG_ERR(( "setsockopt(SOL_SOCKET,SO_SNDBUF,%i) failed (%i-%s)", client->so_sndbuf, errno, fd_io_strerror( errno ) ));

  if( FD_UNLIKELY( -1==connect( client->sockfd, fd_type_pun_const( &addr ), sizeof(struct sockaddr_in) ) && errno!=EINPROGRESS ) ) {
    disconnect( client, DISCONNECT_REASON_CONNECT_FAILED, errno, 1 );
    return;
  }

  client->state = STATE_SENDING_HANDSHAKE;
  client->metrics.transport_success_cnt++;
  FD_LOG_NOTICE(( "connected to event server " FD_IP4_ADDR_FMT ":%u (%.*s)", FD_IP4_ADDR_FMT_ARGS( ip4_addr ), client->server_tcp_port, (int)client->server_fqdn_len, client->server_fqdn ));

  client->sending_handshake.handshake_bytes_sent = 0UL;
  client->sending_handshake.handshake_sent_deadline = now + 1L*1000L*1000L*1000L; /* 1 second timeout */
}

struct __attribute__((__packed__)) handshake {
  char   magic[ 4UL ];
  ulong  version;
  ulong  instance_id;
  ulong  boot_id;
  ulong  machine_id;
  ushort shred_version;
  uchar  genesis_hash[ 32UL ];
  uchar  identity_pubkey[ 32UL ];
  uchar  vote_account_pubkey[ 32UL ]; /* TODO: Remove? */
  char   client_version[ 16UL ];
};

static void
send_handshake( fd_event_client_t * client,
                int *               charge_busy ) {
  FD_TEST( client->state==STATE_SENDING_HANDSHAKE );

  long now = fd_log_wallclock();
  if( FD_UNLIKELY( now>client->sending_handshake.handshake_sent_deadline ) ) {
    *charge_busy = 1;
    disconnect( client, DISCONNECT_REASON_TIMEOUT, 0, 1 );
    return;
  }

  struct handshake hs = {
    .magic         = { 'F', 'D', 'E', 'V' },
    .version       = 1UL,
    .instance_id   = client->instance_id,
    .boot_id       = client->boot_id,
    .machine_id    = client->machine_id,
    .shred_version = client->shred_version,
  };
  fd_memcpy( hs.identity_pubkey, client->identity_pubkey, 32UL );
  fd_memset( hs.client_version, 0, sizeof( hs.client_version ) );
  fd_memcpy( hs.genesis_hash, client->genesis_hash, 32UL );
  fd_memset( hs.vote_account_pubkey, 0, 32UL ); /* TODO: Remove? */
  strncpy( hs.client_version, client->client_version, sizeof( hs.client_version )-1UL );
  hs.client_version[ sizeof( hs.client_version ) - 1UL ] = '\0';

  while( client->sending_handshake.handshake_bytes_sent<sizeof(hs) ) {
    long sent = send( client->sockfd,
                      ((uchar*)&hs)+client->sending_handshake.handshake_bytes_sent,
                      sizeof(hs)-client->sending_handshake.handshake_bytes_sent,
                      MSG_NOSIGNAL );
    if( FD_UNLIKELY( -1==sent && errno==EAGAIN ) ) return;
    *charge_busy = 1;
    if( FD_UNLIKELY( -1==sent ) ) {
      disconnect( client, DISCONNECT_REASON_SEND_FAILED, errno, 1 );
      return;
    }
    client->sending_handshake.handshake_bytes_sent += (ulong)sent;
  }

  client->state = STATE_WAITING_FOR_CHALLENGE;
  client->waiting_for_challenge.challenge_bytes_received = 0UL;
  client->waiting_for_challenge.challenge_deadline = now + 1L*1000L*1000L*1000L; /* 1 second timeout */
}

static void
gather_challenge( fd_event_client_t * client,
                  int *               charge_busy ) {
  FD_TEST( client->state==STATE_WAITING_FOR_CHALLENGE );

  long now = fd_log_wallclock();
  if( FD_UNLIKELY( now>client->waiting_for_challenge.challenge_deadline ) ) {
    *charge_busy = 1;
    disconnect( client, DISCONNECT_REASON_TIMEOUT, 0, 1 );
    return;
  }

  while( client->waiting_for_challenge.challenge_bytes_received<sizeof(client->waiting_for_challenge.challenge) ) {
    long recvd = recv( client->sockfd,
                       ((uchar*)&client->waiting_for_challenge.challenge)+client->waiting_for_challenge.challenge_bytes_received,
                       sizeof(client->waiting_for_challenge.challenge)-client->waiting_for_challenge.challenge_bytes_received,
                       MSG_NOSIGNAL );
    if( FD_UNLIKELY( -1==recvd && errno==EAGAIN ) ) return;
    *charge_busy = 1;
    if( FD_UNLIKELY( -1==recvd ) ) {
      disconnect( client, DISCONNECT_REASON_RECV_FAILED, errno, 1 );
      return;
    } else if( FD_UNLIKELY( !recvd ) ) {
      disconnect( client, DISCONNECT_REASON_PEER_CLOSED, 0, 1 );
      return;
    }

    client->waiting_for_challenge.challenge_bytes_received += (ulong)recvd;
  }

  /* Challenge magic must already be in LE */
  if( FD_UNLIKELY( 0!=memcmp( client->waiting_for_challenge.challenge.magic, "FDEV", 4UL ) ) ) {
    FD_LOG_WARNING(( "invalid challenge magic" ));
    disconnect( client, DISCONNECT_REASON_RECV_FAILED, 0, 1 );
    return;
  }

  fd_keyguard_client_sign( client->keyguard_client,
                           client->sending_challenge_response.signature,
                           client->waiting_for_challenge.challenge.nonce,
                           32UL,
                           FD_KEYGUARD_SIGN_TYPE_FD_METRICS_REPORT_CONCAT_ED25519 );

  client->state = STATE_SENDING_CHALLENGE_RESPONSE;
  client->sending_challenge_response.response_bytes_sent = 0UL;
  client->sending_challenge_response.response_sent_deadline = now + 1L*1000L*1000L*1000L; /* 1 second timeout */
}

static void
send_challenge_response( fd_event_client_t * client,
                        int *                charge_busy ) {
  FD_TEST( client->state==STATE_SENDING_CHALLENGE_RESPONSE );

  long now = fd_log_wallclock();
  if( FD_UNLIKELY( now>client->sending_challenge_response.response_sent_deadline ) ) {
    *charge_busy = 1;
    disconnect( client, DISCONNECT_REASON_TIMEOUT, 0, 1 );
    return;
  }

  while( client->sending_challenge_response.response_bytes_sent<64UL ) {
    long sent = send( client->sockfd,
                      client->sending_challenge_response.signature+client->sending_challenge_response.response_bytes_sent,
                      64UL-client->sending_challenge_response.response_bytes_sent,
                      MSG_NOSIGNAL );
    if( FD_UNLIKELY( -1==sent && errno==EAGAIN ) ) return;
    *charge_busy = 1;
    if( FD_UNLIKELY( -1==sent ) ) {
      FD_LOG_WARNING(( "send() failed (%d-%s)", errno, fd_io_strerror( errno ) ));
      disconnect( client, DISCONNECT_REASON_SEND_FAILED, errno, 1 );
      return;
    }
    client->sending_challenge_response.response_bytes_sent += (ulong)sent;
  }

  client->state = STATE_CONNECTED;
  client->connected.rx.cursor_deadline = now + 1L*1000L*1000L*1000L; /* 1 second timeout */
  client->connected.rx.cursor_bytes_received = 0UL;
  client->connected.tx.has_message = 0;
  client->consecutive_failure_count = 0UL;
}

static void
rx( fd_event_client_t * client,
    int *               charge_busy ) {
  FD_TEST( client->state==STATE_CONNECTED );

  long now = fd_log_wallclock();
  if( FD_UNLIKELY( now>client->connected.rx.cursor_deadline ) ) {
    *charge_busy = 1;
    disconnect( client, DISCONNECT_REASON_TIMEOUT, 0, 1 );
    return;
  }

  FD_TEST( client->connected.rx.cursor_bytes_received<=8UL );
  long recvd = recv( client->sockfd,
                     (uchar*)(&client->connected.rx.cursor)+client->connected.rx.cursor_bytes_received,
                     8UL-client->connected.rx.cursor_bytes_received,
                     MSG_NOSIGNAL );
  if( FD_UNLIKELY( -1==recvd && errno==EAGAIN ) ) return;
  *charge_busy = 1;
  if( FD_UNLIKELY( -1==recvd ) ) {
    disconnect( client, DISCONNECT_REASON_RECV_FAILED, errno, 1 );
    return;
  } else if( FD_UNLIKELY( !recvd ) ) {
    disconnect( client, DISCONNECT_REASON_PEER_CLOSED, 0, 1 );
    return;
  }

  client->connected.rx.cursor_bytes_received += (ulong)recvd;
  if( FD_UNLIKELY( client->connected.rx.cursor_bytes_received==8UL ) ) {
    int err = fd_circq_pop_until( client->circq, client->connected.rx.cursor );
    if( FD_UNLIKELY( -1==err ) ) {
      disconnect( client, DISCONNECT_REASON_INVALID_CURSOR, 0, 1 );
      return;
    }

    client->connected.rx.cursor_bytes_received = 0UL;
    client->connected.rx.cursor_deadline = now + 1L*1000L*1000L*1000L; /* 1 second timeout */
  }
}

static void
tx( fd_event_client_t * client,
    int *               charge_busy ) {
  FD_TEST( client->state==STATE_CONNECTED );

  if( FD_LIKELY( !client->connected.tx.has_message ) ) {
    fd_event_t const * event = fd_type_pun_const( fd_circq_cursor_advance( client->circq ) );
    if( FD_UNLIKELY( !event ) ) return;

    *charge_busy = 1;

    long bytes = fd_event_serialize( event, client->connected.tx.message_bytes, sizeof(client->connected.tx.message_bytes) );
    if( FD_UNLIKELY( bytes<0 ) ) {
      /* Do not disconnect here.  We want to skip this message and not
         try to send it again. */
      FD_LOG_WARNING(( "failed to serialize event %u, %ld, skipping", event->tag, bytes ));
      return;
    }

    client->connected.tx.has_message = 1;
    client->connected.tx.message_bytes_sent = 0UL;
    client->connected.tx.message_bytes_len  = (ulong)bytes;
  }

  while( client->connected.tx.message_bytes_sent<client->connected.tx.message_bytes_len ) {
    long sent = send( client->sockfd,
                      client->connected.tx.message_bytes+client->connected.tx.message_bytes_sent,
                      client->connected.tx.message_bytes_len-client->connected.tx.message_bytes_sent,
                      MSG_NOSIGNAL );
    if( FD_UNLIKELY( -1==sent && errno==EAGAIN ) ) return;
    *charge_busy = 1;
    if( FD_UNLIKELY( -1==sent ) ) {
      disconnect( client, DISCONNECT_REASON_SEND_FAILED, errno, 1 );
      return;
    }
    client->connected.tx.message_bytes_sent += (ulong)sent;
  }

  client->connected.tx.has_message = 0;
}

void
fd_event_client_poll( fd_event_client_t * client,
                      int *               charge_busy ) {
  if( FD_UNLIKELY( !client->has_genesis_hash || !client->has_shred_version ) ) return;

  if( FD_UNLIKELY( client->state==STATE_DISCONNECTED ) ) reconnect( client, charge_busy );
  if( FD_UNLIKELY( client->state==STATE_SENDING_HANDSHAKE ) ) send_handshake( client, charge_busy );
  if( FD_UNLIKELY( client->state==STATE_WAITING_FOR_CHALLENGE ) ) gather_challenge( client, charge_busy );
  if( FD_UNLIKELY( client->state==STATE_SENDING_CHALLENGE_RESPONSE ) ) send_challenge_response( client, charge_busy );
  if( FD_LIKELY( client->state==STATE_CONNECTED ) ) {
    rx( client, charge_busy );
    if( FD_LIKELY( client->state==STATE_CONNECTED ) ) tx( client, charge_busy );
  }
}
