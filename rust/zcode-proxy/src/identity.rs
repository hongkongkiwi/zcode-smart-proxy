//! Durable per-account device identities.

use rand::{rngs::OsRng, RngCore};
use rusqlite::Connection;

use crate::{state::AppState, store::StoreError};

fn new_identity() -> Result<String, StoreError> {
    let mut bytes = [0_u8; 16];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| StoreError::Database)?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex = bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    ))
}

pub(crate) fn ensure_locked(db: &Connection, id: i64) -> Result<String, StoreError> {
    let tx = db.unchecked_transaction()?;
    let mut mid: String =
        tx.query_row("SELECT device_mid FROM accounts WHERE id=?1", [id], |r| {
            r.get(0)
        })?;
    if mid.is_empty() {
        let candidate = new_identity()?;
        tx.execute(
            "UPDATE accounts SET device_mid=?1 WHERE id=?2 AND device_mid=''",
            rusqlite::params![candidate, id],
        )?;
        mid = tx.query_row("SELECT device_mid FROM accounts WHERE id=?1", [id], |r| {
            r.get(0)
        })?;
        if mid.is_empty() {
            return Err(StoreError::Database);
        }
    }
    tx.commit()?;
    Ok(mid)
}

pub fn ensure_device_identity(state: &AppState, id: i64) -> Result<String, StoreError> {
    ensure_locked(&state.db.lock().unwrap(), id)
}

pub fn backfill_device_identities(state: &AppState) -> Result<usize, StoreError> {
    let mut db = state.db.lock().unwrap();
    let tx = db.transaction()?;
    let ids = {
        let mut stmt = tx.prepare("SELECT id FROM accounts WHERE device_mid='' ORDER BY id")?;
        let rows = stmt.query_map([], |r| r.get::<_, i64>(0))?;
        rows.collect::<rusqlite::Result<Vec<_>>>()?
    };
    let mut count = 0;
    for id in ids {
        let mid = new_identity()?;
        count += tx.execute(
            "UPDATE accounts SET device_mid=?1 WHERE id=?2 AND device_mid=''",
            rusqlite::params![mid, id],
        )?;
    }
    tx.commit()?;
    Ok(count)
}
