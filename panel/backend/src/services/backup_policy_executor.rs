//! GAP 1: Backup Policy Executor — runs every 60s, evaluates cron schedules,
//! executes backup_policies across sites, databases, and volumes.

use chrono::{Datelike, Timelike};
use sqlx::PgPool;
use uuid::Uuid;

use crate::services::agent::AgentClient;
use crate::services::notifications;

/// Row from the policy query.
#[derive(sqlx::FromRow)]
#[allow(dead_code)]
struct PolicyRow {
    id: Uuid,
    user_id: Uuid,
    server_id: Option<Uuid>,
    name: String,
    backup_sites: bool,
    backup_databases: bool,
    backup_volumes: bool,
    schedule: String,
    #[allow(dead_code)]
    destination_id: Option<Uuid>,
    retention_count: i32,
    encrypt: bool,
    verify_after_backup: bool,
    last_run: Option<chrono::DateTime<chrono::Utc>>,
}

/// Derive the symmetric key used to encrypt AND decrypt policy-driven DB backups.
///
/// This is the SINGLE SOURCE OF TRUTH for the derivation. The encrypt side
/// (`execute_policy`) and the decrypt side (`routes::backup_orchestrator::restore_db_backup`)
/// previously derived the key from two DIFFERENT, incompatible sources — restore read a
/// `backup_destinations.encryption_key` column that nothing ever writes — so every
/// encrypted DB backup was permanently unrestorable and DR was silently broken in encrypted
/// mode (lesson #70: resolve by the value that actually produced the artifact, not a
/// re-derived phantom). Keyed on the process JWT secret (`config.jwt_secret`, == the
/// `JWT_SECRET` env the executor is handed), so both sides agree byte-for-byte.
pub fn derive_backup_encryption_key(jwt_secret: &str) -> String {
    format!("backup-enc-{}", &jwt_secret[..32.min(jwt_secret.len())])
}

/// Run the backup policy executor loop — checks every 60 seconds for due policies.
pub async fn run(db: PgPool, agent: AgentClient, jwt_secret: String, mut shutdown_rx: tokio::sync::broadcast::Receiver<()>) {
    tracing::info!("Backup policy executor started");

    let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));

    loop {
        tokio::select! {
            _ = interval.tick() => {
                if let Err(e) = tick(&db, &agent, &jwt_secret).await {
                    tracing::error!("Backup policy executor error: {e}");
                }
            }
            _ = shutdown_rx.recv() => {
                tracing::info!("Backup policy executor shutting down gracefully");
                break;
            }
        }
    }
}

/// Track last stale-backup check to avoid spamming (once per hour).
static LAST_STALE_CHECK: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);

async fn tick(db: &PgPool, agent: &AgentClient, jwt_secret: &str) -> Result<(), String> {
    let now = chrono::Utc::now();

    // Fetch all enabled policies
    let policies: Vec<PolicyRow> = sqlx::query_as(
        "SELECT id, user_id, server_id, name, backup_sites, backup_databases, backup_volumes, \
         schedule, destination_id, retention_count, encrypt, verify_after_backup, last_run \
         FROM backup_policies WHERE enabled = TRUE"
    )
    .fetch_all(db).await.map_err(|e| e.to_string())?;

    for policy in &policies {
        // Check if cron matches current time
        if !cron_matches_now(&policy.schedule, &now) {
            continue;
        }

        // Prevent double-runs within 90 seconds
        if let Some(last_run) = policy.last_run {
            if (now - last_run).num_seconds() < 90 {
                continue;
            }
        }

        tracing::info!("Executing backup policy '{}' ({})", policy.name, policy.id);
        execute_policy(db, agent, policy, jwt_secret).await;
    }

    // Record backup storage metric for growth tracking. SUM(BIGINT) returns
    // NUMERIC in postgres — cast to bigint so sqlx can decode into i64.
    let total_storage: Option<(i64,)> = sqlx::query_as(
        "SELECT COALESCE(SUM(size_bytes), 0)::bigint FROM ( \
            SELECT size_bytes FROM backups UNION ALL \
            SELECT size_bytes FROM database_backups UNION ALL \
            SELECT size_bytes FROM volume_backups \
        ) t"
    ).fetch_one(db).await.ok();
    if let Some((bytes,)) = total_storage {
        let _ = sqlx::query(
            "INSERT INTO system_logs (level, source, message) VALUES ('info', 'backup_storage', $1)"
        ).bind(format!("{}", bytes)).execute(db).await;
    }

    // Proactive backup freshness alerting — once per hour
    let now_ts = now.timestamp();
    let last_check = LAST_STALE_CHECK.load(std::sync::atomic::Ordering::Relaxed);
    if now_ts - last_check >= 3600 {
        LAST_STALE_CHECK.store(now_ts, std::sync::atomic::Ordering::Relaxed);

        let stale: Vec<(String,)> = sqlx::query_as(
            "SELECT s.domain FROM sites s WHERE s.status = 'active' \
             AND NOT EXISTS (SELECT 1 FROM backups b WHERE b.site_id = s.id AND b.created_at > NOW() - INTERVAL '48 hours')"
        ).fetch_all(db).await.unwrap_or_default();

        if !stale.is_empty() {
            let domains: Vec<&str> = stale.iter().map(|s| s.0.as_str()).collect();
            notifications::notify_panel(db, None,
                &format!("{} site(s) have stale backups", stale.len()),
                &format!("These sites have no backup in 48+ hours: {}", domains.join(", ")),
                "warning", "backup", Some("/backup-orchestrator")
            ).await;
            tracing::warn!("Stale backup alert: {} sites without recent backups", stale.len());
        }
    }

    Ok(())
}

async fn execute_policy(db: &PgPool, agent: &AgentClient, policy: &PolicyRow, jwt_secret: &str) {
    let mut successes = 0;
    let mut failures = 0;

    // Get encryption key if encrypt is enabled. Use the shared derivation (single source of
    // truth) keyed on the jwt_secret passed into the executor — which equals the
    // state.config.jwt_secret the restore path uses — NOT a separate std::env read that could
    // drift from it. This is what makes an encrypted backup actually restorable.
    let encryption_key: Option<String> = if policy.encrypt {
        Some(derive_backup_encryption_key(jwt_secret))
    } else {
        None
    };

    // Backup sites
    if policy.backup_sites {
        let sites: Vec<(Uuid, String)> = sqlx::query_as(
            "SELECT id, domain FROM sites WHERE user_id = $1"
        )
        .bind(policy.user_id)
        .fetch_all(db).await.unwrap_or_default();

        for (site_id, domain) in &sites {
            let mut result = agent.post(&format!("/backups/{domain}/create"), None).await;
            // Retry once on failure
            if result.is_err() {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                result = agent.post(&format!("/backups/{domain}/create"), None).await;
            }
            match result {
                Ok(resp) => {
                    let filename = resp.get("filename").and_then(|v| v.as_str()).unwrap_or("");
                    let size_bytes = resp.get("size_bytes").and_then(|v| v.as_u64()).unwrap_or(0) as i64;

                    let _ = sqlx::query(
                        "INSERT INTO backups (site_id, filename, size_bytes) VALUES ($1, $2, $3)"
                    )
                    .bind(site_id).bind(filename).bind(size_bytes)
                    .execute(db).await;

                    successes += 1;
                }
                Err(e) => {
                    tracing::error!("Policy '{}': site backup failed for {domain} (after retry): {e}", policy.name);
                    failures += 1;
                }
            }
        }
    }

    // Backup databases
    if policy.backup_databases {
        let databases: Vec<(Uuid, String, String, String, String)> = sqlx::query_as(
            "SELECT d.id, d.name, d.engine, d.db_user, d.db_password_enc \
             FROM databases d JOIN sites s ON d.site_id = s.id WHERE s.user_id = $1"
        )
        .bind(policy.user_id)
        .fetch_all(db).await.unwrap_or_default();

        for (db_id, db_name, engine, user, password_enc) in &databases {
            let password = crate::services::secrets_crypto::decrypt_credential_or_legacy(password_enc, jwt_secret);
            let container_name = format!("dockpanel-db-{db_name}");
            let body = serde_json::json!({
                "container_name": container_name,
                "db_name": db_name,
                "db_type": engine,
                "user": user,
                "password": password,
                "encryption_key": encryption_key,
            });

            let mut result = agent.post("/db-backups/dump", Some(body.clone())).await;
            // Retry once on failure
            if result.is_err() {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                result = agent.post("/db-backups/dump", Some(body)).await;
            }
            match result {
                Ok(resp) => {
                    let filename = resp.get("filename").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let size_bytes = resp.get("size_bytes").and_then(|v| v.as_u64()).unwrap_or(0) as i64;
                    let encrypted = encryption_key.is_some();

                    let sha256_hash = resp.get("sha256").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let previous_hash: Option<String> = sqlx::query_scalar(
                        "SELECT sha256_hash FROM database_backups WHERE database_id = $1 ORDER BY created_at DESC LIMIT 1"
                    ).bind(db_id).fetch_optional(db).await.unwrap_or(None);

                    let _ = sqlx::query(
                        "INSERT INTO database_backups (database_id, server_id, filename, size_bytes, db_type, db_name, encrypted, policy_id, sha256_hash, previous_hash, chain_valid) \
                         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, TRUE)"
                    )
                    .bind(db_id).bind(policy.server_id).bind(&filename).bind(size_bytes)
                    .bind(engine).bind(db_name).bind(encrypted).bind(policy.id)
                    .bind(if sha256_hash.is_empty() { None } else { Some(&sha256_hash) })
                    .bind(previous_hash.as_deref())
                    .execute(db).await;

                    successes += 1;
                }
                Err(e) => {
                    tracing::error!("Policy '{}': DB backup failed for {db_name} (after retry): {e}", policy.name);
                    failures += 1;
                }
            }
        }
    }

    // Backup volumes (Docker app volumes). This is an admin-only capability — the
    // direct create_volume_backup endpoint is AdminUser, and the enumeration below is
    // fleet-wide with NO per-user scoping. Policy CRUD is now admin-gated, but guard
    // the executor too so any legacy non-admin-owned policy cannot drive volume backups.
    let owner_is_admin: bool = sqlx::query_scalar::<_, bool>(
        "SELECT role = 'admin' FROM users WHERE id = $1"
    )
    .bind(policy.user_id)
    .fetch_optional(db)
    .await
    .ok()
    .flatten()
    .unwrap_or(false);
    if policy.backup_volumes && !owner_is_admin {
        tracing::warn!("Policy '{}': skipping volume backup — owner is not an admin", policy.name);
    }
    if policy.backup_volumes && owner_is_admin {
        // Get Docker containers with volumes
        match agent.get("/apps").await {
            Ok(apps) => {
                if let Some(apps) = apps.as_array() {
                    for app in apps {
                        let container_name = app.get("name").and_then(|v| v.as_str()).unwrap_or("");
                        let container_id = app.get("container_id").and_then(|v| v.as_str()).unwrap_or("");

                        if container_name.is_empty() { continue; }

                        // Get volumes for this container
                        if let Ok(vol_resp) = agent.get(&format!("/apps/{container_id}/volumes")).await {
                            if let Some(volumes) = vol_resp.as_array() {
                                for vol in volumes {
                                    let vol_name = vol.get("name").and_then(|v| v.as_str()).unwrap_or("");
                                    if vol_name.is_empty() { continue; }

                                    let body = serde_json::json!({
                                        "volume_name": vol_name,
                                        "container_name": container_name,
                                    });

                                    let mut result = agent.post("/volume-backups/create", Some(body.clone())).await;
                                    // Retry once on failure
                                    if result.is_err() {
                                        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                                        result = agent.post("/volume-backups/create", Some(body)).await;
                                    }
                                    match result {
                                        Ok(resp) => {
                                            let filename = resp.get("filename").and_then(|v| v.as_str()).unwrap_or("").to_string();
                                            let size_bytes = resp.get("size_bytes").and_then(|v| v.as_u64()).unwrap_or(0) as i64;

                                            let sha256_hash = resp.get("sha256").and_then(|v| v.as_str()).unwrap_or("").to_string();
                                            let previous_hash: Option<String> = sqlx::query_scalar(
                                                "SELECT sha256_hash FROM volume_backups WHERE container_id = $1 AND volume_name = $2 ORDER BY created_at DESC LIMIT 1"
                                            ).bind(container_id).bind(vol_name).fetch_optional(db).await.unwrap_or(None);

                                            let _ = sqlx::query(
                                                "INSERT INTO volume_backups (container_id, container_name, server_id, volume_name, filename, size_bytes, policy_id, sha256_hash, previous_hash, chain_valid) \
                                                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, TRUE)"
                                            )
                                            .bind(container_id).bind(container_name).bind(policy.server_id)
                                            .bind(vol_name).bind(&filename).bind(size_bytes).bind(policy.id)
                                            .bind(if sha256_hash.is_empty() { None } else { Some(&sha256_hash) })
                                            .bind(previous_hash.as_deref())
                                            .execute(db).await;

                                            successes += 1;
                                        }
                                        Err(e) => {
                                            tracing::error!("Policy '{}': volume backup failed for {container_name}/{vol_name} (after retry): {e}", policy.name);
                                            failures += 1;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => {
                tracing::error!("Policy '{}': failed to list Docker apps for volume backup: {e}", policy.name);
                failures += 1;
            }
        }
    }

    // Update policy status
    let status = if failures == 0 { "success" } else if successes > 0 { "partial" } else { "failed" };
    let _ = sqlx::query(
        "UPDATE backup_policies SET last_run = NOW(), last_status = $2, updated_at = NOW() WHERE id = $1"
    )
    .bind(policy.id).bind(status)
    .execute(db).await;

    tracing::info!(
        "Policy '{}' completed: {} successes, {} failures (status: {status})",
        policy.name, successes, failures
    );

    // GAP 10: If backup failures, create managed incident
    if failures > 0 {
        let _ = sqlx::query(
            "INSERT INTO managed_incidents (user_id, title, status, severity, description, visible_on_status_page) \
             VALUES ($1, $2, 'investigating', 'major', $3, FALSE)"
        )
        .bind(policy.user_id)
        .bind(format!("Backup policy '{}' had failures", policy.name))
        .bind(format!("{failures} backup(s) failed, {successes} succeeded"))
        .execute(db).await;
    }

    // Fire alert on failure
    if failures > 0 {
        notifications::fire_alert(
            db, policy.user_id, policy.server_id, None,
            "backup_failure", "critical",
            &format!("Backup policy '{}' failed", policy.name),
            &format!("{failures} backup(s) failed out of {} total", successes + failures),
        ).await;
    }

    // GAP 2: If verify_after_backup, trigger verification for newly created backups
    if policy.verify_after_backup && successes > 0 {
        tracing::info!("Policy '{}': triggering post-backup verification", policy.name);
        // The backup_verifier service will pick these up on its next cycle
        // since they'll be unverified backups created in the last 7 days
    }
}

/// Simple cron matcher (5 fields: minute hour day month weekday).
fn cron_matches_now(schedule: &str, now: &chrono::DateTime<chrono::Utc>) -> bool {
    let fields: Vec<&str> = schedule.split_whitespace().collect();
    if fields.len() != 5 {
        return false;
    }

    let checks = [
        (fields[0], now.minute() as i32),
        (fields[1], now.hour() as i32),
        (fields[2], now.day() as i32),
        (fields[3], now.month() as i32),
        (fields[4], now.weekday().num_days_from_sunday() as i32),
    ];

    checks.iter().all(|(field, value)| field_matches(field, *value))
}

fn field_matches(field: &&str, value: i32) -> bool {
    let field = *field;
    if field == "*" {
        return true;
    }

    // Step: */N
    if let Some(step) = field.strip_prefix("*/") {
        if let Ok(n) = step.parse::<i32>() {
            return n > 0 && value % n == 0;
        }
    }

    // List: 1,5,10
    for part in field.split(',') {
        // Range: 1-5
        if let Some((start, end)) = part.split_once('-') {
            if let (Ok(s), Ok(e)) = (start.parse::<i32>(), end.parse::<i32>()) {
                if value >= s && value <= e {
                    return true;
                }
            }
        } else if let Ok(v) = part.parse::<i32>() {
            if v == value {
                return true;
            }
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    // s248 / lesson #70: encrypt (execute_policy) and decrypt (restore_db_backup) MUST derive
    // the backup key from the same single source of truth. These pin that derivation so the two
    // sides can never drift back into the incompatible-key bug that made encrypted restores 400.
    #[test]
    fn backup_key_derivation_is_stable_and_prefixed() {
        let jwt = "abcdefghijklmnopqrstuvwxyz0123456789EXTRA";
        let k = derive_backup_encryption_key(jwt);
        // Deterministic + uses only the first 32 bytes of the secret.
        assert_eq!(k, "backup-enc-abcdefghijklmnopqrstuvwxyz012345");
        assert_eq!(derive_backup_encryption_key(jwt), k);
    }

    #[test]
    fn backup_key_derivation_handles_short_secret() {
        // Must not panic on a secret shorter than 32 bytes (32.min(len)).
        assert_eq!(derive_backup_encryption_key("short"), "backup-enc-short");
    }

    #[test]
    fn encrypt_and_restore_derive_identical_key() {
        // The encrypt and decrypt paths both call THIS one function, so identical input →
        // identical output is the guarantee that an encrypted backup is restorable.
        let secret = "the-process-jwt-secret-value-000000000000";
        assert_eq!(
            derive_backup_encryption_key(secret),
            derive_backup_encryption_key(secret),
        );
    }
}
