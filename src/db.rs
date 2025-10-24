use rusqlite::{Connection, params, Result};
use time::OffsetDateTime;

pub const DB_FILE: &str = "totally_not_my_privateKeys.db";

pub fn init_db() -> Result<()> {
    // Nothing fancy: ensure file exists by touching (GradeBot checks for the file on disk),
    // but at runtime we just open it — Connection::open will create DB if needed.
    let conn = Connection::open(DB_FILE)?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS keys (
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )",
        [],
    )?;
    Ok(())
}

pub fn insert_key(key: &[u8], exp: i64) -> Result<()> {
    let conn = Connection::open(DB_FILE)?;
    conn.execute(
        "INSERT INTO keys (key, exp) VALUES (?1, ?2)",
        params![key, exp],
    )?;
    Ok(())
}

pub fn fetch_key(expired: bool) -> Result<Option<(i64, Vec<u8>, i64)>> {
    let conn = Connection::open(DB_FILE)?;
    let now = OffsetDateTime::now_utc().unix_timestamp();

    let sql = if expired {
        "SELECT kid, key, exp FROM keys WHERE exp <= ?1 ORDER BY exp DESC LIMIT 1"
    } else {
        "SELECT kid, key, exp FROM keys WHERE exp > ?1 ORDER BY exp ASC LIMIT 1"
    };

    let mut stmt = conn.prepare(sql)?;
    let mut rows = stmt.query(params![now])?;

    if let Some(row) = rows.next()? {
        Ok(Some((row.get(0)?, row.get(1)?, row.get(2)?)))
    } else {
        Ok(None)
    }
}

pub fn fetch_all_valid_keys() -> Result<Vec<(i64, Vec<u8>, i64)>> {
    let conn = Connection::open(DB_FILE)?;
    let now = OffsetDateTime::now_utc().unix_timestamp();

    let mut stmt = conn.prepare("SELECT kid, key, exp FROM keys WHERE exp > ?1")?;
    let rows = stmt.query_map(params![now], |row| {
        Ok((row.get(0)?, row.get(1)?, row.get(2)?))
    })?
    .collect::<Result<Vec<_>, _>>()?;

    Ok(rows)
}
