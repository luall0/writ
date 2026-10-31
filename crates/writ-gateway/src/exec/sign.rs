//! `writ-sign`: the object on stdin signed with the daemon's key, the armored SSHSIG on
//! stdout. Until M3's `Signer` and checks, any active lease with `commit_sign` may sign.

use russh::ChannelReadHalf;
use tokio::io::AsyncReadExt;
use writ_crypto::sshsig;

use crate::Gateway;

/// Largest object accepted for signing.
pub const MAX_SIGN_INPUT: u64 = 16 * 1024 * 1024;

/// The armored SSHSIG over the object read from the channel, or why it can't be signed.
pub(super) async fn sign(
    gateway: &Gateway,
    namespace: &str,
    rx: &mut ChannelReadHalf,
) -> Result<String, String> {
    let mut object = Vec::new();
    rx.make_reader()
        .take(MAX_SIGN_INPUT + 1)
        .read_to_end(&mut object)
        .await
        .map_err(|e| format!("cannot read the object: {e}"))?;
    if object.len() as u64 > MAX_SIGN_INPUT {
        return Err("object too large to sign".to_owned());
    }
    sshsig::sign(&gateway.shared.config.signing_key, namespace, &object).map_err(|e| e.to_string())
}
