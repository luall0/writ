//! Answering on an SSH channel: stdout, the reason on stderr (`writ: <reason>`), the exit
//! status, then the channel closes.

use russh::server::Msg;
use russh::{Channel, ChannelWriteHalf};

/// Fails the command with a reason the client sees on stderr.
pub(crate) async fn refuse(channel: Channel<Msg>, reason: String) {
    let (_, tx) = channel.split();
    fail(&tx, &reason).await;
}

/// Writes `writ: <reason>` on stderr and ends the command with status 1.
pub(crate) async fn fail(tx: &ChannelWriteHalf<Msg>, reason: &str) {
    let _ = tx
        .extended_data_bytes(1, format!("writ: {reason}\n").into_bytes())
        .await;
    finish(tx, 1).await;
}

/// Writes a reply: `stdout`, then the failure on stderr (status 1) or nothing (status 0).
pub(crate) async fn reply(tx: ChannelWriteHalf<Msg>, (stdout, failure): (Vec<u8>, Option<String>)) {
    let _ = tx.data_bytes(stdout).await;
    match failure {
        Some(reason) => fail(&tx, &reason).await,
        None => finish(&tx, 0).await,
    }
}

/// Sends the exit status and closes the channel.
pub(crate) async fn finish(tx: &ChannelWriteHalf<Msg>, code: u32) {
    let _ = tx.exit_status(code).await;
    let _ = tx.eof().await;
    let _ = tx.close().await;
}
