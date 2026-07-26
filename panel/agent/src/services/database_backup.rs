use std::path::PathBuf;
use tokio::io::AsyncWriteExt;
use crate::safe_cmd::safe_command;

use super::backups::{BackupInfo, compute_file_sha256};

const BACKUP_DIR: &str = "/var/backups/dockpanel/databases";

/// Validate backup filename (prevent path traversal).
fn is_safe_filename(name: &str) -> bool {
    !name.is_empty()
        && !name.contains('/')
        && !name.contains("..")
        && (name.ends_with(".sql.gz") || name.ends_with(".archive.gz") || name.ends_with(".sql.gz.enc") || name.ends_with(".archive.gz.enc"))
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
}

fn backup_dir(db_name: &str) -> PathBuf {
    PathBuf::from(format!("{BACKUP_DIR}/{db_name}"))
}

/// Validate container/db/user names to prevent argument injection.
/// These must be alphanumeric + underscore/hyphen only.
fn is_safe_db_identifier(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && !name.contains("..")
        && !name.contains('/')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
        && !name.starts_with('-')
}

/// Dump a MySQL/MariaDB database from its Docker container.
///
/// Uses piped `docker exec` → `gzip` to avoid shell interpolation entirely.
pub async fn dump_mysql(
    container_name: &str,
    db_name: &str,
    user: &str,
    password: &str,
) -> Result<BackupInfo, String> {
    if !is_safe_db_identifier(container_name) {
        return Err("Invalid container name".into());
    }
    if !is_safe_db_identifier(db_name) {
        return Err("Invalid database name".into());
    }
    if !is_safe_db_identifier(user) {
        return Err("Invalid username".into());
    }

    let dest_dir = backup_dir(db_name);
    std::fs::create_dir_all(&dest_dir)
        .map_err(|e| format!("Failed to create backup dir: {e}"))?;

    let timestamp = chrono::Utc::now().format("%Y%m%d-%H%M%S");
    let filename = format!("{db_name}-{timestamp}.sql.gz");
    let filepath = dest_dir.join(&filename);
    let _filepath_str = filepath.to_str().ok_or("Invalid path encoding")?;

    // docker exec outputs to stdout → pipe to gzip → write to file
    let mut docker_child = safe_command("docker")
        .args([
            "exec",
            "-e", &format!("MYSQL_PWD={password}"),
            container_name,
            "mariadb-dump",
            "-u", user,
            "--single-transaction", "--routines", "--triggers",
            db_name,
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to spawn docker exec: {e}"))?;

    let docker_stdout = docker_child.stdout.take()
        .ok_or("Failed to capture docker stdout")?;

    let mut gzip_child = safe_command("gzip")
        .stdin(docker_stdout.into_owned_fd().map_err(|_| "Failed to get fd")?)
        .stdout(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to spawn gzip: {e}"))?;

    let gzip_stdout = gzip_child.stdout.take()
        .ok_or("Failed to capture gzip stdout")?;

    // Write gzip output to file
    let filepath_clone = filepath.clone();
    let write_handle = tokio::spawn(async move {
        
        let mut reader = gzip_stdout;
        let mut file = tokio::fs::File::create(&filepath_clone).await?;
        tokio::io::copy(&mut reader, &mut file).await?;
        file.flush().await?;
        Ok::<_, std::io::Error>(())
    });

    let result = tokio::time::timeout(
        std::time::Duration::from_secs(600),
        async {
            let docker_status = docker_child.wait().await
                .map_err(|e| format!("docker exec wait error: {e}"))?;
            let _gzip_status = gzip_child.wait().await
                .map_err(|e| format!("gzip wait error: {e}"))?;
            write_handle.await
                .map_err(|e| format!("write task error: {e}"))?
                .map_err(|e| format!("file write error: {e}"))?;
            if !docker_status.success() {
                return Err("MySQL dump failed (docker exec returned non-zero)".to_string());
            }
            Ok(())
        }
    )
    .await
    .map_err(|_| "Database dump timed out (10 minutes)".to_string())?;

    if let Err(e) = result {
        std::fs::remove_file(&filepath).ok();
        return Err(e);
    }

    let meta = std::fs::metadata(&filepath)
        .map_err(|e| format!("Failed to read dump metadata: {e}"))?;
    if meta.len() < 30 {
        std::fs::remove_file(&filepath).ok();
        return Err("Database dump produced empty output".to_string());
    }

    let filepath_str = filepath.to_str().ok_or("Invalid path encoding")?;
    let sha256 = compute_file_sha256(filepath_str).await;

    tracing::info!("MySQL dump created: {filename} ({} bytes, hash: {})", meta.len(), sha256.as_deref().unwrap_or("N/A"));

    Ok(BackupInfo {
        filename,
        size_bytes: meta.len(),
        created_at: chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        sha256,
        ..Default::default()
    })
}

/// Dump a PostgreSQL database from its Docker container.
pub async fn dump_postgres(
    container_name: &str,
    db_name: &str,
    user: &str,
    password: &str,
) -> Result<BackupInfo, String> {
    if !is_safe_db_identifier(container_name) {
        return Err("Invalid container name".into());
    }
    if !is_safe_db_identifier(db_name) {
        return Err("Invalid database name".into());
    }
    if !is_safe_db_identifier(user) {
        return Err("Invalid username".into());
    }

    let dest_dir = backup_dir(db_name);
    std::fs::create_dir_all(&dest_dir)
        .map_err(|e| format!("Failed to create backup dir: {e}"))?;

    let timestamp = chrono::Utc::now().format("%Y%m%d-%H%M%S");
    let filename = format!("{db_name}-{timestamp}.sql.gz");
    let filepath = dest_dir.join(&filename);
    let _filepath_str = filepath.to_str().ok_or("Invalid path encoding")?;

    let mut docker_child = safe_command("docker")
        .args([
            "exec",
            "-e", &format!("PGPASSWORD={password}"),
            container_name,
            "pg_dump",
            "-U", user,
            "-d", db_name,
            // --clean --if-exists so a restore OVERWRITES the target rather than merging
            // into it (without --clean, restoring into a non-empty DB appends/errors per
            // object and silently yields a merge). Pairs with the ON_ERROR_STOP +
            // --single-transaction restore below.
            "--no-owner", "--no-acl", "--clean", "--if-exists",
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to spawn docker exec: {e}"))?;

    let docker_stdout = docker_child.stdout.take()
        .ok_or("Failed to capture docker stdout")?;

    let mut gzip_child = safe_command("gzip")
        .stdin(docker_stdout.into_owned_fd().map_err(|_| "Failed to get fd")?)
        .stdout(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to spawn gzip: {e}"))?;

    let gzip_stdout = gzip_child.stdout.take()
        .ok_or("Failed to capture gzip stdout")?;

    let filepath_clone = filepath.clone();
    let write_handle = tokio::spawn(async move {
        let mut reader = gzip_stdout;
        let mut file = tokio::fs::File::create(&filepath_clone).await?;
        tokio::io::copy(&mut reader, &mut file).await?;
        file.flush().await?;
        Ok::<_, std::io::Error>(())
    });

    let result = tokio::time::timeout(
        std::time::Duration::from_secs(600),
        async {
            let docker_status = docker_child.wait().await
                .map_err(|e| format!("docker exec wait error: {e}"))?;
            let _gzip_status = gzip_child.wait().await
                .map_err(|e| format!("gzip wait error: {e}"))?;
            write_handle.await
                .map_err(|e| format!("write task error: {e}"))?
                .map_err(|e| format!("file write error: {e}"))?;
            if !docker_status.success() {
                return Err("PostgreSQL dump failed (docker exec returned non-zero)".to_string());
            }
            Ok(())
        }
    )
    .await
    .map_err(|_| "Database dump timed out (10 minutes)".to_string())?;

    if let Err(e) = result {
        std::fs::remove_file(&filepath).ok();
        return Err(e);
    }

    let meta = std::fs::metadata(&filepath)
        .map_err(|e| format!("Failed to read dump metadata: {e}"))?;
    if meta.len() < 30 {
        std::fs::remove_file(&filepath).ok();
        return Err("Database dump produced empty output".to_string());
    }

    let filepath_str = filepath.to_str().ok_or("Invalid path encoding")?;
    let sha256 = compute_file_sha256(filepath_str).await;

    tracing::info!("PostgreSQL dump created: {filename} ({} bytes, hash: {})", meta.len(), sha256.as_deref().unwrap_or("N/A"));

    Ok(BackupInfo {
        filename,
        size_bytes: meta.len(),
        created_at: chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        sha256,
        ..Default::default()
    })
}

/// Dump a MongoDB database from its Docker container.
pub async fn dump_mongo(
    container_name: &str,
    db_name: &str,
) -> Result<BackupInfo, String> {
    if !is_safe_db_identifier(container_name) {
        return Err("Invalid container name".into());
    }
    if !is_safe_db_identifier(db_name) {
        return Err("Invalid database name".into());
    }

    let dest_dir = backup_dir(db_name);
    std::fs::create_dir_all(&dest_dir)
        .map_err(|e| format!("Failed to create backup dir: {e}"))?;

    let timestamp = chrono::Utc::now().format("%Y%m%d-%H%M%S");
    let filename = format!("{db_name}-{timestamp}.archive.gz");
    let filepath = dest_dir.join(&filename);
    let _filepath_str = filepath.to_str().ok_or("Invalid path encoding")?;

    // mongodump --archive --gzip streams the archive on stdout. Stream it straight to the
    // dump file rather than buffering the ENTIRE archive in the agent's RAM via .output() —
    // a multi-GB Mongo DB would OOM-kill the shared root agent (a tenant-triggerable
    // cross-tenant DoS). The mysql/pg dump paths already stream via fd pipes; do the same
    // here. stderr is still captured for the failure message; stdout goes to the file fd.
    let output = tokio::time::timeout(
        std::time::Duration::from_secs(600),
        async {
            let file = std::fs::File::create(&filepath)
                .map_err(|e| format!("Failed to create dump file: {e}"))?;
            let child = safe_command("docker")
                .args([
                    "exec", container_name,
                    "mongodump", "--db", db_name, "--archive", "--gzip",
                ])
                .stdout(std::process::Stdio::from(file))
                .stderr(std::process::Stdio::piped())
                // Kill mongodump if this future is dropped (e.g. the outer timeout fires), so it
                // stops streaming into the dump file the moment we give up on it.
                .kill_on_drop(true)
                .spawn()
                .map_err(|e| format!("Failed to run mongodump: {e}"))?;

            let child_output = child.wait_with_output().await
                .map_err(|e| format!("mongodump wait error: {e}"))?;

            if !child_output.status.success() {
                let stderr = String::from_utf8_lossy(&child_output.stderr);
                return Err(format!("MongoDB dump failed: {stderr}"));
            }
            Ok(())
        }
    )
    .await;

    // On timeout the mongodump child is dropped (kill_on_drop=true) and killed, but the
    // partially-streamed dump file remains on disk — remove it so it can't later surface as a
    // "restorable" backup (the old .output() path never created a file until after success, so
    // this cleanup is new-code-specific). Clean up on a normal dump error too.
    let output = match output {
        Ok(inner) => inner,
        Err(_) => {
            std::fs::remove_file(&filepath).ok();
            return Err("Database dump timed out (10 minutes)".to_string());
        }
    };
    if let Err(e) = output {
        std::fs::remove_file(&filepath).ok();
        return Err(e);
    }

    let meta = std::fs::metadata(&filepath)
        .map_err(|e| format!("Failed to read dump metadata: {e}"))?;
    if meta.len() < 30 {
        std::fs::remove_file(&filepath).ok();
        return Err("Database dump produced empty output".to_string());
    }

    let filepath_str = filepath.to_str().ok_or("Invalid path encoding")?;
    let sha256 = compute_file_sha256(filepath_str).await;

    tracing::info!("MongoDB dump created: {filename} ({} bytes, hash: {})", meta.len(), sha256.as_deref().unwrap_or("N/A"));

    Ok(BackupInfo {
        filename,
        size_bytes: meta.len(),
        created_at: chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        sha256,
        ..Default::default()
    })
}

/// Restore a MySQL/MariaDB database from a backup file.
pub async fn restore_mysql(
    container_name: &str,
    db_name: &str,
    user: &str,
    password: &str,
    filepath: &str,
) -> Result<(), String> {
    if !is_safe_db_identifier(container_name) {
        return Err("Invalid container name".into());
    }
    if !is_safe_db_identifier(db_name) {
        return Err("Invalid database name".into());
    }
    if !is_safe_db_identifier(user) {
        return Err("Invalid username".into());
    }

    // gunzip → pipe to docker exec mysql
    let mut gunzip_child = safe_command("gunzip")
        .args(["-c", filepath])
        .stdout(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to spawn gunzip: {e}"))?;

    let gunzip_stdout = gunzip_child.stdout.take()
        .ok_or("Failed to capture gunzip stdout")?;

    let docker_child = safe_command("docker")
        .args([
            "exec", "-i",
            "-e", &format!("MYSQL_PWD={password}"),
            container_name,
            // `mariadb`, NOT `mysql`: the panel provisions `mariadb:11`, and
            // MariaDB 11 dropped the mysql-named client symlinks, so `mysql`
            // does not exist in the container at all. Every sibling call site
            // (database.rs, backup_drill.rs, backup_verify.rs) already invokes
            // `mariadb`; this one did not, so restoring a MySQL/MariaDB dump
            // failed on every install with "executable file not found" while
            // the DUMP half — which correctly calls `mariadb-dump` — worked.
            "mariadb", "-u", user, db_name,
        ])
        .stdin(gunzip_stdout.into_owned_fd().map_err(|_| "Failed to get fd")?)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to spawn docker exec: {e}"))?;

    let result = tokio::time::timeout(
        std::time::Duration::from_secs(600),
        async {
            // Fail the restore if decompression did not complete cleanly — a truncated
            // .gz that ends on a statement boundary otherwise imports partially and the
            // mysql client exits 0 (EOF-as-success).
            let gunzip_status = gunzip_child.wait().await
                .map_err(|e| format!("gunzip wait error: {e}"))?;
            let docker_output = docker_child.wait_with_output().await
                .map_err(|e| format!("docker exec wait error: {e}"))?;
            if !gunzip_status.success() {
                return Err("MySQL restore failed: backup decompression error (truncated/corrupt archive)".to_string());
            }
            if !docker_output.status.success() {
                let stderr = String::from_utf8_lossy(&docker_output.stderr);
                let stderr = stderr.trim();
                // Never report a bare "restore failed:" with nothing after it —
                // a failure with no reason is unactionable, and this path can
                // fail with empty stderr (e.g. the client binary is missing and
                // the runtime writes nothing we captured).
                if stderr.is_empty() {
                    return Err(format!(
                        "MySQL restore failed: the mariadb client exited with {} and produced no error output",
                        docker_output.status
                    ));
                }
                return Err(format!("MySQL restore failed: {stderr}"));
            }
            Ok(())
        }
    )
    .await
    .map_err(|_| "Database restore timed out (10 minutes)".to_string())?;

    result?;
    tracing::info!("MySQL database {db_name} restored from {filepath}");
    Ok(())
}

/// Restore a PostgreSQL database from a backup file.
pub async fn restore_postgres(
    container_name: &str,
    db_name: &str,
    user: &str,
    password: &str,
    filepath: &str,
) -> Result<(), String> {
    if !is_safe_db_identifier(container_name) {
        return Err("Invalid container name".into());
    }
    if !is_safe_db_identifier(db_name) {
        return Err("Invalid database name".into());
    }
    if !is_safe_db_identifier(user) {
        return Err("Invalid username".into());
    }

    let mut gunzip_child = safe_command("gunzip")
        .args(["-c", filepath])
        .stdout(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to spawn gunzip: {e}"))?;

    let gunzip_stdout = gunzip_child.stdout.take()
        .ok_or("Failed to capture gunzip stdout")?;

    let docker_child = safe_command("docker")
        .args([
            "exec", "-i",
            "-e", &format!("PGPASSWORD={password}"),
            container_name,
            // ON_ERROR_STOP=1 + --single-transaction make the restore fail-and-rollback on
            // ANY statement error instead of psql's default (continue-on-error, exit 0),
            // which reported partial/failed restores as success.
            "psql", "-v", "ON_ERROR_STOP=1", "--single-transaction", "-U", user, "-d", db_name,
        ])
        .stdin(gunzip_stdout.into_owned_fd().map_err(|_| "Failed to get fd")?)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to spawn docker exec: {e}"))?;

    let result = tokio::time::timeout(
        std::time::Duration::from_secs(600),
        async {
            // A truncated/corrupt .gz makes gunzip exit non-zero while psql sees a clean
            // EOF at a statement boundary and exits 0 — the classic EOF-as-success trap.
            // Fail the restore if decompression did not complete cleanly.
            let gunzip_status = gunzip_child.wait().await
                .map_err(|e| format!("gunzip wait error: {e}"))?;
            let docker_output = docker_child.wait_with_output().await
                .map_err(|e| format!("docker exec wait error: {e}"))?;
            if !gunzip_status.success() {
                return Err("PostgreSQL restore failed: backup decompression error (truncated/corrupt archive)".to_string());
            }
            if !docker_output.status.success() {
                let stderr = String::from_utf8_lossy(&docker_output.stderr);
                return Err(format!("PostgreSQL restore failed: {stderr}"));
            }
            Ok(())
        }
    )
    .await
    .map_err(|_| "Database restore timed out (10 minutes)".to_string())?;

    result?;
    tracing::info!("PostgreSQL database {db_name} restored from {filepath}");
    Ok(())
}

/// Restore a MongoDB database from a backup file.
pub async fn restore_mongo(
    container_name: &str,
    db_name: &str,
    filepath: &str,
) -> Result<(), String> {
    if !is_safe_db_identifier(container_name) {
        return Err("Invalid container name".into());
    }
    if !is_safe_db_identifier(db_name) {
        return Err("Invalid database name".into());
    }

    // Stream the archive from disk to mongorestore's stdin instead of reading the ENTIRE
    // file into RAM (tokio::fs::read) — a multi-GB archive would OOM the shared root agent
    // (same cross-tenant DoS class as the dump path). tokio::io::copy pipes in bounded chunks.
    let mut file = tokio::fs::File::open(filepath).await
        .map_err(|e| format!("Failed to open backup file: {e}"))?;

    let mut docker_child = safe_command("docker")
        .args([
            "exec", "-i", container_name,
            "mongorestore", "--db", db_name, "--archive", "--gzip", "--drop",
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to spawn docker exec: {e}"))?;

    let mut stdin = docker_child.stdin.take()
        .ok_or("Failed to capture docker stdin")?;

    let write_handle = tokio::spawn(async move {
        tokio::io::copy(&mut file, &mut stdin).await?;
        stdin.shutdown().await?;
        Ok::<_, std::io::Error>(())
    });

    let result = tokio::time::timeout(
        std::time::Duration::from_secs(600),
        async {
            write_handle.await
                .map_err(|e| format!("write task error: {e}"))?
                .map_err(|e| format!("stdin write error: {e}"))?;
            let docker_output = docker_child.wait_with_output().await
                .map_err(|e| format!("docker exec wait error: {e}"))?;
            if !docker_output.status.success() {
                let stderr = String::from_utf8_lossy(&docker_output.stderr);
                return Err(format!("MongoDB restore failed: {stderr}"));
            }
            Ok(())
        }
    )
    .await
    .map_err(|_| "Database restore timed out (10 minutes)".to_string())?;

    result?;
    tracing::info!("MongoDB database {db_name} restored from {filepath}");
    Ok(())
}

/// List database backups for a given database name.
pub fn list_db_backups(db_name: &str) -> Result<Vec<BackupInfo>, String> {
    let dir = backup_dir(db_name);
    if !dir.exists() {
        return Ok(Vec::new());
    }

    let mut backups = Vec::new();
    for entry in std::fs::read_dir(&dir).map_err(|e| format!("Read dir error: {e}"))? {
        let entry = entry.map_err(|e| format!("Entry error: {e}"))?;
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.ends_with(".sql.gz") && !name.ends_with(".archive.gz")
            && !name.ends_with(".sql.gz.enc") && !name.ends_with(".archive.gz.enc")
        {
            continue;
        }
        let meta = entry.metadata().ok();
        let size = meta.as_ref().map(|m| m.len()).unwrap_or(0);
        let created = meta
            .as_ref()
            .and_then(|m| m.modified().ok())
            .map(|t| {
                let dt: chrono::DateTime<chrono::Utc> = t.into();
                dt.format("%Y-%m-%d %H:%M:%S").to_string()
            })
            .unwrap_or_default();

        backups.push(BackupInfo {
            filename: name,
            size_bytes: size,
            created_at: created,
            sha256: None,
        ..Default::default()
    });
    }

    backups.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    Ok(backups)
}

/// Delete a database backup file.
pub fn delete_db_backup(db_name: &str, filename: &str) -> Result<(), String> {
    if !is_safe_filename(filename) {
        return Err("Invalid backup filename".into());
    }

    let filepath = backup_dir(db_name).join(filename);
    if !filepath.exists() {
        return Err("Backup file not found".into());
    }

    std::fs::remove_file(&filepath)
        .map_err(|e| format!("Failed to delete backup: {e}"))?;

    tracing::info!("Database backup deleted: {filename} for {db_name}");
    Ok(())
}

/// Get the full filesystem path for a database backup file.
pub fn get_backup_path(db_name: &str, filename: &str) -> Result<String, String> {
    if !is_safe_filename(filename) {
        return Err("Invalid backup filename".into());
    }
    let filepath = backup_dir(db_name).join(filename);
    if !filepath.exists() {
        return Err("Backup file not found".into());
    }
    filepath
        .to_str()
        .map(|s| s.to_string())
        .ok_or_else(|| "Invalid path encoding".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_db_identifier_rejects_traversal() {
        // Traversal sequences must be rejected even though '.' is allowed in the charset.
        assert!(!is_safe_db_identifier(".."));
        assert!(!is_safe_db_identifier("../etc"));
        assert!(!is_safe_db_identifier("a/../b"));
        assert!(!is_safe_db_identifier("foo/bar"));
        assert!(!is_safe_db_identifier("-leadingdash"));
        assert!(!is_safe_db_identifier(""));
        // Legitimate identifiers still pass.
        assert!(is_safe_db_identifier("wordpress"));
        assert!(is_safe_db_identifier("my_db-01"));
        assert!(is_safe_db_identifier("dockpanel-db-wordpress"));
    }

    #[test]
    fn safe_filename_rejects_traversal_and_bad_ext() {
        assert!(!is_safe_filename("../evil.sql.gz"));
        assert!(!is_safe_filename("a/b.sql.gz"));
        assert!(!is_safe_filename("dump.txt"));
        assert!(is_safe_filename("wordpress-20260722-120000.sql.gz"));
        assert!(is_safe_filename("db-20260722-120000.archive.gz.enc"));
    }
}
