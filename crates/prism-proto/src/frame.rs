// SPDX-License-Identifier: AGPL-3.0-or-later
//! Length-prefixed framing over `tokio` byte streams.
//!
//! Wire format of one frame: a 4-byte big-endian unsigned length, followed by
//! that many bytes of JSON body. The length is validated against
//! [`MAX_FRAME_LEN`] before any buffer is allocated, so a hostile peer cannot
//! force a large allocation with a forged prefix.

use std::io::ErrorKind;

use serde::{de::DeserializeOwned, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroizing;

use crate::ProtoError;

/// Maximum accepted frame body size (64 KiB). IPC control messages are tiny;
/// this bound is generous while still rejecting abusive lengths early.
pub const MAX_FRAME_LEN: u32 = 64 * 1024;

/// Serialize `message` to JSON and write it as one length-prefixed frame.
pub async fn write_message<W, T>(writer: &mut W, message: &T) -> Result<(), ProtoError>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    // Zeroized on drop: the serialized body may contain secrets (passphrase,
    // mnemonic) in the clear.
    let body = Zeroizing::new(serde_json::to_vec(message)?);
    let len =
        u32::try_from(body.len()).map_err(|_| ProtoError::FrameTooLarge { len: body.len() })?;
    if len > MAX_FRAME_LEN {
        return Err(ProtoError::FrameTooLarge { len: body.len() });
    }
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(&body).await?;
    writer.flush().await?;
    Ok(())
}

/// Read exactly one length-prefixed frame and deserialize it.
///
/// Returns [`ProtoError::UnexpectedEof`] if the connection closes before a
/// complete frame is received. Use [`read_message_opt`] to treat a clean EOF
/// (peer closed the connection between frames) as a normal end of stream.
pub async fn read_message<R, T>(reader: &mut R) -> Result<T, ProtoError>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    match read_message_opt(reader).await? {
        Some(message) => Ok(message),
        None => Err(ProtoError::UnexpectedEof),
    }
}

/// Like [`read_message`], but returns `Ok(None)` on a clean EOF before any
/// bytes of the next frame are received (the peer closed the connection).
pub async fn read_message_opt<R, T>(reader: &mut R) -> Result<Option<T>, ProtoError>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let mut len_buf = [0u8; 4];
    match reader.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(ProtoError::Io(e)),
    }

    let len = u32::from_be_bytes(len_buf);
    if len > MAX_FRAME_LEN {
        return Err(ProtoError::FrameTooLarge { len: len as usize });
    }

    // Zeroized on drop: the received body may contain secrets (passphrase,
    // mnemonic) in the clear.
    let mut body = Zeroizing::new(vec![0u8; len as usize]);
    reader.read_exact(&mut body).await?;
    let message = serde_json::from_slice(&body)?;
    Ok(Some(message))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Envelope, Request, PROTOCOL_VERSION};
    use tokio::io::duplex;

    #[tokio::test]
    async fn round_trip_preserves_message_and_version() {
        let (mut client, mut server) = duplex(1024);
        write_message(&mut client, &Envelope::new(Request::Ping))
            .await
            .expect("write should succeed");

        let received: Envelope<Request> = read_message(&mut server)
            .await
            .expect("read should succeed");
        assert_eq!(received.version, PROTOCOL_VERSION);
        assert!(matches!(received.message, Request::Ping));
    }

    #[tokio::test]
    async fn clean_eof_between_frames_returns_none() {
        let (client, mut server) = duplex(1024);
        drop(client); // peer closes without sending anything

        let received: Option<Envelope<Request>> = read_message_opt(&mut server)
            .await
            .expect("read_opt should succeed");
        assert!(received.is_none());
    }

    #[tokio::test]
    async fn oversized_length_prefix_is_rejected_before_allocating() {
        let (mut client, mut server) = duplex(1024);
        let bogus_len = MAX_FRAME_LEN + 1;
        client
            .write_all(&bogus_len.to_be_bytes())
            .await
            .expect("write len prefix");

        let result: Result<Envelope<Request>, ProtoError> = read_message(&mut server).await;
        assert!(matches!(result, Err(ProtoError::FrameTooLarge { .. })));
    }

    #[tokio::test]
    async fn truncated_frame_is_a_clean_error_not_a_hang() {
        let (mut client, mut server) = duplex(1024);
        // Announce a 100-byte body, send only 3 bytes, then close the connection.
        client
            .write_all(&100u32.to_be_bytes())
            .await
            .expect("write len prefix");
        client
            .write_all(&[1, 2, 3])
            .await
            .expect("write partial body");
        drop(client);

        // Must resolve promptly to an error, never hang waiting for the rest.
        let result: Result<Envelope<Request>, ProtoError> =
            tokio::time::timeout(std::time::Duration::from_secs(5), read_message(&mut server))
                .await
                .expect("read must complete, not hang");
        assert!(matches!(result, Err(ProtoError::Io(_))));
    }
}
