#include "fd_event.h"

#include "../../util/log/fd_log.h"

long
fd_event_serialize( fd_event_t const * event,
                    uchar *            buf,
                    ulong              buf_sz ) {
  (void)event; (void)buf; (void)buf_sz;

  FD_LOG_ERR(( "fd_event_serialize not implemented" ));
}
