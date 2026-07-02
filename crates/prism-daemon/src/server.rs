// SPDX-License-Identifier: AGPL-3.0-or-later
//! IPC server: accept loop, peer-credential check, and request dispatch.

use prism_proto::{
    read_message_opt, write_message, Envelope, ProtoError, Request, Response, PROTOCOL_VERSION,
};
use tokio::net::{UnixListener, UnixStream};
use tracing::{debug, warn};

use crate::DaemonError;

/// Accept connections on `listener` forever, serving each authorized client.
///
/// Every incoming connection is checked with `SO_PEERCRED`: only a peer whose
/// UID matches the daemon's own UID is served. Any other peer, or a peer whose
/// credentials cannot be read, is dropped. Authorized connections are handled
/// on their own task.
pub async fn serve(listener: UnixListener) -> Result<(), DaemonError> {
    let our_uid = rustix::process::getuid().as_raw();

    loop {
        let (stream, _addr) = listener.accept().await?;
        match stream.peer_cred() {
            Ok(cred) if cred.uid() == our_uid => {
                debug!("accepted IPC connection from the owning user");
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(stream).await {
                        warn!(error = %e, "IPC connection ended with an error");
                    }
                });
            }
            Ok(cred) => {
                warn!(
                    peer_uid = cred.uid(),
                    "rejected IPC connection from a different user"
                );
            }
            Err(e) => {
                warn!(error = %e, "rejected IPC connection: could not read peer credentials");
            }
        }
    }
}

/// Serve requests on a single connection until the peer closes it.
async fn handle_connection(mut stream: UnixStream) -> Result<(), ProtoError> {
    while let Some(envelope) = read_message_opt::<_, Envelope<Request>>(&mut stream).await? {
        let response = dispatch(envelope);
        write_message(&mut stream, &Envelope::new(response)).await?;
    }
    Ok(())
}

/// Map a versioned request to a response, rejecting unsupported versions.
fn dispatch(envelope: Envelope<Request>) -> Response {
    if envelope.version != PROTOCOL_VERSION {
        return Response::Error {
            message: format!(
                "unsupported IPC protocol version {} (this daemon speaks {})",
                envelope.version, PROTOCOL_VERSION
            ),
        };
    }

    match envelope.message {
        Request::Ping => Response::Pong,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ping_is_answered_with_pong() {
        let response = dispatch(Envelope::new(Request::Ping));
        assert_eq!(response, Response::Pong);
    }

    #[test]
    fn unsupported_version_is_rejected() {
        let envelope = Envelope {
            version: PROTOCOL_VERSION.wrapping_add(1),
            message: Request::Ping,
        };
        assert!(matches!(dispatch(envelope), Response::Error { .. }));
    }
}
