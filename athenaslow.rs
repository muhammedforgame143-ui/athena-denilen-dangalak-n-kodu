use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use chrono::{DateTime, Utc};
use tokio::sync::Mutex;

use crate::boost_poll::wait_for_drop;
use crate::boost_watch::run_boost_rest_watch;
use crate::signal_watch::run_signal_rest_watch;
use crate::fleet::TriggerMode;
use crate::fleet::EngineConfig;
use crate::fire::{scheduled_tls_fire, warm_tls, MfaCache, MfaMeta};
use crate::tls_pool;
use crate::gw::{run_gw_listeners, WatchState};
use crate::mfa::fetch_mfa_cancellable;
use crate::schedule::build_shot_delays;
use crate::shots::{build_shots, unique_tokens};
use crate::subs::DropHint;
use crate::webhook::{send_webhook, send_webhook_with_content};

const MFA_PERIOD_MS: u64 = 240_000;
const HOT_TAIL_MS: u64 = 120_000;

#[derive(Clone)]
struct MfaManager {
    cache: MfaCache,
    busy: Arc<Mutex<bool>>,
    quiet_until: Arc<Mutex<Option<Instant>>>,
    /// Boost/fire gelince true â€” devam eden MFA iptal, cache ile vur
    abort: Arc<AtomicBool>,
}

impl MfaManager {
    fn new() -> Self {
        Self {
            cache: Arc::new(Mutex::new(HashMap::new())),
            busy: Arc::new(Mutex::new(false)),
            quiet_until: Arc::new(Mutex::new(None)),
            abort: Arc::new(AtomicBool::new(false)),
        }
    }

    fn abort_for_fire(&self, name: &str) {
        if !self.abort.swap(true, Ordering::SeqCst) {
            tracing::warn!(
                "[{name}] MFA IPTAL â€” boost/fire, devam eden yenileme durduruluyor, cache ile vurulacak"
            );
        }
    }

    fn aborted(&self) -> bool {
        self.abort.load(Ordering::Relaxed)
    }

    async fn set_quiet_for_drop(&self, ends_at: DateTime<Utc>, tail_ms: u64) {
        let until_drop = (ends_at - Utc::now()).num_milliseconds().max(0) as u64;
        let ms = until_drop + tail_ms;
        *self.quiet_until.lock().await = Some(Instant::now() + Duration::from_millis(ms));
    }

    async fn in_quiet(&self) -> bool {
        match *self.quiet_until.lock().await {
            Some(until) if Instant::now() < until => true,
            _ => false,
        }
    }

    async fn refresh_all(&self, cfg: &EngineConfig, force: bool) -> (usize, usize) {
        if self.aborted() {
            return self.count_ok(cfg).await;
        }
        if !force && self.in_quiet().await {
            return self.count_ok(cfg).await;
        }
        {
            let mut busy = self.busy.lock().await;
            if *busy {
                return self.count_ok(cfg).await;
            }
            *busy = true;
        }
        let (ok, total) = do_refresh_mfa(cfg, &self.cache, &self.abort).await;
        *self.busy.lock().await = false;
        (ok, total)
    }

    async fn count_ok(&self, cfg: &EngineConfig) -> (usize, usize) {
        let lanes = unique_tokens(cfg.lanes);
        let total = lanes.len();
        let guard = self.cache.lock().await;
        let ok = lanes
            .iter()
            .filter(|l| guard.contains_key(l.token))
            .count();
        (ok, total)
    }
}

pub struct Engine {
    cfg: EngineConfig,
    watch: WatchState,
    mfa: MfaManager,
}

impl Engine {
    pub fn new(cfg: EngineConfig) -> Self {
        Self {
            cfg,
            watch: WatchState::new(),
            mfa: MfaManager::new(),
        }
    }

    pub async fn run(self) -> Result<()> {
        let cfg = self.cfg.clone();
        let name = cfg.name;

        tracing::info!(
            "[{name}] {} boot fire={} t0={}ms t1={}ms tls-only shots={}",
            EngineConfig::FLEET,
            cfg.host,
            cfg.t0_ms,
            cfg.t1_ms,
            cfg.shot_cap
        );

        let drop = wait_for_drop(&cfg).await?;

        {
            let mut v = self.watch.vanity.lock().await;
            *v = drop.vanity.to_lowercase();
            *self.watch.gid.lock().await = drop.gid.clone();
        }
        tracing::info!(
            "[{name}] WATCH preset gg/{} gid={} (subs)",
            drop.vanity,
            drop.gid
        );

        let hot_tail = cfg.t1_ms + HOT_TAIL_MS;
        let mfa = self.mfa.clone();
        mfa.set_quiet_for_drop(drop.ends_at, hot_tail).await;

        let ms_until = (drop.ends_at - Utc::now()).num_milliseconds().max(0) as u64;
        let early = cfg.mfa_early_ms;
        let final_lead = cfg.mfa_final_ms;
        let mut did_boot_mfa = false;

        let watch_state = self.watch.clone();
        let engine_cfg = cfg.clone();
        let mfa_fire = mfa.clone();
        let on_arm: Arc<dyn Fn(u32, &'static str) + Send + Sync> = Arc::new(move |boost, source| {
            let cfg = engine_cfg.clone();
            let watch = watch_state.clone();
            let mfa = mfa_fire.clone();
            tokio::spawn(async move {
                let kod = cfg.name;
                if let Err(e) = try_fire(cfg, watch, mfa, boost, source).await {
                    tracing::error!("[{kod}] FIRE ERR {e}");
                }
            });
        });

        let mut gw_spawned = false;
        let gw_watch_base = self.watch.clone();
        let gw_spawn = |gw_spawned: &mut bool| {
            if *gw_spawned {
                return;
            }
            *gw_spawned = true;
            let gw_cfg = cfg.clone();
            let gw_watch = gw_watch_base.clone();
            let gw_on_arm = on_arm.clone();
            tokio::spawn(async move {
                run_gw_listeners(&gw_cfg, gw_watch, gw_on_arm).await;
            });
            tracing::info!("[{name}] GW baÅŸladÄ± (Ã§ift baÄŸlantÄ±/listener)");
        };
        gw_spawn(&mut gw_spawned);

        {
            let rest_cfg = cfg.clone();
            let rest_watch = self.watch.clone();
            let rest_on_arm = on_arm.clone();
            let ends_at = drop.ends_at;
            tokio::spawn(async move {
                run_boost_rest_watch(rest_cfg, rest_watch, ends_at, rest_on_arm).await;
            });
            tracing::info!("[{name}] REST boost watch planlandi (T-30s - T+120s, 600ms poll)");
        }

        {
            let sig_cfg = cfg.clone();
            let sig_watch = self.watch.clone();
            let sig_on_arm = on_arm.clone();
            let ends_at = drop.ends_at;
            tokio::spawn(async move {
                run_signal_rest_watch(sig_cfg, sig_watch, ends_at, sig_on_arm).await;
            });
        }

        // >5dk: MFA hemen | â‰¤5dk: T-1dk'ya kadar bekle
        if ms_until > early {
            tracing::info!("[{name}] drop {ms_until}ms sonra â€” MFA ÅŸimdi (>{}ms)", early);
            let (ok, total) = mfa.refresh_all(&cfg, true).await;
            tracing::info!("[{name}] MFA {ok}/{total} (boot)");
            mfa_status_webhook(&cfg, &drop, ok, total, "boot").await;
            did_boot_mfa = true;
            gw_spawn(&mut gw_spawned);
        }

        if ms_until > final_lead {
            if !did_boot_mfa {
                tracing::info!("[{name}] drop â‰¤5dk â€” T-1dk MFA iÃ§in bekleniyor");
            }
            sleep_until_before(drop.ends_at, final_lead, name, "T-1dk MFA").await;
        } else if !did_boot_mfa {
            tracing::info!("[{name}] drop â‰¤1dk â€” MFA ÅŸimdi");
        }

        let (ok, total) = mfa.refresh_all(&cfg, true).await;
        tracing::info!("[{name}] MFA {ok}/{total} (T-1dk)");
        mfa_status_webhook(&cfg, &drop, ok, total, "T-1dk").await;
        warm_tls(cfg.host, 4).await;

        let period_cfg = cfg.clone();
        let period_mfa = mfa.clone();
        let period_watch = self.watch.clone();
        tokio::spawn(async move {
            mfa_periodic_loop(period_cfg, period_mfa, period_watch).await;
        });

        if !gw_spawned {
            let warmup_left = (drop.ends_at
                - chrono::Duration::milliseconds(cfg.gw_warmup_ms as i64)
                - Utc::now())
            .num_milliseconds();
            if warmup_left > 0 {
                sleep_until_before(drop.ends_at, cfg.gw_warmup_ms, name, "GW warmup").await;
            }
            gw_spawn(&mut gw_spawned);
        } else if cfg.gw_warmup_ms > 0 {
            let warmup_left = (drop.ends_at
                - chrono::Duration::milliseconds(cfg.gw_warmup_ms as i64)
                - Utc::now())
            .num_milliseconds();
            if warmup_left > 0 {
                sleep_until_before(drop.ends_at, cfg.gw_warmup_ms, name, "GW warmup").await;
            }
        }

        sleep_until_before(drop.ends_at, cfg.gw_lead_ms, name, "GW kritik").await;

        tracing::info!(
            "[{name}] GW dinleniyor boost<{} â€” GUILD_UPDATE â†’ PATCH {}â€“{}ms",
            cfg.boost_below,
            cfg.t0_ms,
            cfg.t1_ms
        );
        tokio::signal::ctrl_c().await?;
        Ok(())
    }
}

async fn sleep_until_before(
    ends_at: DateTime<Utc>,
    lead_ms: u64,
    name: &'static str,
    phase: &str,
) {
    let target = ends_at - chrono::Duration::milliseconds(lead_ms as i64);
    let left = (target - Utc::now()).num_milliseconds();
    if left > 0 {
        tracing::info!("[{name}] {phase} â€” {left}ms bekleniyor");
        tokio::time::sleep(Duration::from_millis(left as u64)).await;
    }
}

fn patch_window_desc(cfg: &EngineConfig) -> String {
    if let Some(s) = cfg.split_schedule {
        format!(
            "10@0ms + {}@{}â€“{}ms + {}@{}â€“{}ms",
            s.mid_count,
            s.mid_start_ms,
            s.mid_end_ms,
            s.tail_count,
            s.tail_start_ms,
            s.tail_end_ms
        )
    } else {
        format!("{}â€“{}ms", cfg.t0_ms, cfg.t1_ms)
    }
}

async fn mfa_status_webhook(
    cfg: &EngineConfig,
    drop: &DropHint,
    ok: usize,
    total: usize,
    phase: &str,
) {
    if total == 0 {
        return;
    }
    let gw_at = drop.ends_at - chrono::Duration::milliseconds(cfg.gw_lead_ms as i64);
    let icon = if ok == total {
        "âœ…"
    } else if ok > 0 {
        "âšï¸"
    } else {
        "âŒ"
    };
    let desc = format!(
        "**{ok}/{total}** MFA â€” patch hazÄ±r\n\n\
        gg/**{}** gid=`{}`\n\
        Drop: **{}** UTC\n\
        GW: **{}** UTC (T-{}s)\n\
        PATCH: **{}** boost<{} sonrasÄ±\n\
        Sonraki MFA: T-1dk sonra her **{}dk**\n\
        Faz: **{phase}**",
        drop.vanity,
        drop.gid,
        drop.ends_at.format("%Y-%m-%d %H:%M:%S"),
        gw_at.format("%H:%M:%S"),
        cfg.gw_lead_ms / 1000,
        patch_window_desc(cfg),
        cfg.boost_below,
        MFA_PERIOD_MS / 60_000,
    );
    let color = if ok == total {
        0x57F287
    } else if ok > 0 {
        0xFEE75C
    } else {
        0xED4245
    };
    let _ = send_webhook(
        cfg.webhook,
        &format!("{icon} {} | {} | MFA", EngineConfig::FLEET, cfg.name),
        &desc,
        color,
    )
    .await;
}

async fn mfa_periodic_loop(cfg: EngineConfig, mfa: MfaManager, watch: WatchState) {
    let mut tick = tokio::time::interval(Duration::from_millis(MFA_PERIOD_MS));
    tick.tick().await;
    loop {
        tick.tick().await;
        if *watch.fired.lock().await || mfa.aborted() {
            tracing::info!("[{}] MFA periyodik durdu â€” ateÅŸ edildi", cfg.name);
            break;
        }
        let (ok, total) = mfa.refresh_all(&cfg, true).await;
        tracing::info!("[{}] MFA periyodik {ok}/{total}", cfg.name);
    }
}

async fn try_fire(
    cfg: EngineConfig,
    watch: WatchState,
    mfa: MfaManager,
    boost: u32,
    source: &str,
) -> Result<()> {
    if *watch.fired.lock().await {
        tracing::info!("[{}] FIRE skip â€” zaten atÄ±ldÄ± ({source})", cfg.name);
        return Ok(());
    }

    let wave = match cfg.trigger {
        TriggerMode::BoostWindow
        | TriggerMode::BoostZero
        | TriggerMode::PowerupL3Delete
        | TriggerMode::FeatureVanityUrl
        | TriggerMode::TierDrop
        | TriggerMode::ApiGuild
        | TriggerMode::GwThenApiGuild
        | TriggerMode::ApiInvite
        | TriggerMode::RestL3Gone => {
            // tek dalga â€” t0..t1 schedule
            if matches!(
                cfg.trigger,
                TriggerMode::ApiGuild
                    | TriggerMode::GwThenApiGuild
                    | TriggerMode::ApiInvite
                    | TriggerMode::RestL3Gone
            ) {
                let ok = match cfg.trigger {
                    TriggerMode::ApiGuild | TriggerMode::GwThenApiGuild => {
                        source.starts_with("API-GUILD")
                    }
                    TriggerMode::ApiInvite => source.starts_with("API-INVITE"),
                    TriggerMode::RestL3Gone => source.contains("REST-L3"),
                    _ => true,
                };
                if !ok {
                    tracing::info!(
                        "[{}] trigger {:?} â€” sinyal yok sayildi ({source})",
                        cfg.name,
                        cfg.trigger
                    );
                    return Ok(());
                }
            }
            None
        }
        TriggerMode::L3GwThenRest { gw_shots, rest_shots } => {
            if source.contains("REST-L3") {
                let mut once = watch.done_rest_l3.lock().await;
                if *once {
                    return Ok(());
                }
                *once = true;
                Some(rest_shots as usize)
            } else if source.contains("L3-DELETE") || source.contains("POWERUP") {
                let mut once = watch.done_gw_l3.lock().await;
                if *once {
                    return Ok(());
                }
                *once = true;
                Some(gw_shots as usize)
            } else {
                tracing::info!(
                    "[{}] trigger L3GwThenRest â€” boost sinyali yok sayildi ({source})",
                    cfg.name
                );
                return Ok(());
            }
        }
        TriggerMode::ApiPowerupsSubs { wave_shots } => {
            if source.starts_with("API-") {
                Some(wave_shots as usize)
            } else {
                tracing::info!(
                    "[{}] trigger ApiPowerupsSubs â€” boost yok sayildi ({source})",
                    cfg.name
                );
                return Ok(());
            }
        }
    };

    arm_and_fire(cfg, watch, mfa, boost, source, wave).await
}

async fn do_refresh_mfa(
    cfg: &EngineConfig,
    cache: &MfaCache,
    abort: &AtomicBool,
) -> (usize, usize) {
    let lanes = unique_tokens(cfg.lanes);
    let total = lanes.len();
    let mut ok = 0usize;
    let now = Instant::now();
    for (i, lane) in lanes.into_iter().enumerate() {
        if abort.load(Ordering::Relaxed) {
            tracing::warn!("[{}] MFA refresh yarÄ±da iptal ({ok}/{total} hazÄ±r)", cfg.name);
            break;
        }
        if i > 0 && !sleep_abortable(4000, abort).await {
            tracing::warn!("[{}] MFA refresh bekleme iptal ({ok}/{total} hazÄ±r)", cfg.name);
            break;
        }
        if abort.load(Ordering::Relaxed) {
            break;
        }
        match fetch_mfa_cancellable(lane.token, lane.password, lane.gid, abort).await {
            Ok(res) => {
                cache.lock().await.insert(
                    lane.token.to_string(),
                    MfaMeta {
                        token: res.token,
                        cookie: res.cookie,
                        fetched_at: now,
                    },
                );
                tracing::info!("[{}] MFA OK {}", cfg.name, lane.lab);
                ok += 1;
            }
            Err(e) => {
                if abort.load(Ordering::Relaxed) {
                    tracing::info!("[{}] MFA {} iptal (boost/fire)", cfg.name, lane.lab);
                    break;
                }
                tracing::warn!("[{}] MFA ERR {} {e}", cfg.name, lane.lab);
            }
        }
    }
    (ok, total)
}

/// 4sn lane arasÄ± bekleme â€” abort ile kesilebilir
async fn sleep_abortable(ms: u64, abort: &AtomicBool) -> bool {
    let steps = ms.div_ceil(50);
    for _ in 0..steps {
        if abort.load(Ordering::Relaxed) {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    !abort.load(Ordering::Relaxed)
}

async fn arm_and_fire(
    cfg: EngineConfig,
    watch: WatchState,
    mgr: MfaManager,
    boost: u32,
    source: &str,
    wave_limit: Option<usize>,
) -> Result<()> {
    mgr.abort_for_fire(&cfg.name);

    let vanity = watch.vanity.lock().await.clone();
    if vanity.is_empty() {
        tracing::warn!("[{}] SKIP FIRE vanity yok ({source})", cfg.name);
        // once flag geri al â€” tekrar denenebilsin
        if source.contains("REST-L3") {
            *watch.done_rest_l3.lock().await = false;
        } else if source.contains("L3-DELETE") || source.contains("POWERUP") {
            *watch.done_gw_l3.lock().await = false;
        }
        let _ = send_webhook(
            cfg.webhook,
            &format!("âšï¸ {} | {} | SKIP", EngineConfig::FLEET, cfg.name),
            "vanity boÅŸ â€” subs preset yok",
            0xFEE75C,
        )
        .await;
        return Ok(());
    }

    // tek dalga: vanity OK sonrasi fired kilidi
    if wave_limit.is_none() {
        let mut fired = watch.fired.lock().await;
        if *fired {
            return Ok(());
        }
        *fired = true;
    }

    let t0 = Instant::now();
    tracing::info!(
        "[{}] FIRE [{source}] boost={boost} vanity={vanity} window={}â€“{}ms",
        cfg.name,
        cfg.t0_ms,
        cfg.t1_ms
    );

    let shots_plan = build_shots(&cfg);
    // multi-wave: offset rezerve et (race yok)
    let mut mark_fired = false;
    let slice: Vec<_> = {
        let mut used = watch.shots_used.lock().await;
        match wave_limit {
            Some(n) => {
                if *used >= shots_plan.len() {
                    tracing::warn!("[{}] shot butcesi bitti", cfg.name);
                    mark_fired = true;
                    Vec::new()
                } else {
                    let start = *used;
                    let end = (start + n).min(shots_plan.len());
                    *used = end;
                    if *used >= shots_plan.len().min(cfg.shot_cap.max(22)) {
                        mark_fired = true;
                    }
                    shots_plan[start..end].to_vec()
                }
            }
            None => shots_plan.clone(),
        }
    };
    if mark_fired {
        *watch.fired.lock().await = true;
    }
    if slice.is_empty() && wave_limit.is_some() {
        return Ok(());
    }
    let delays = if wave_limit.is_some() {
        vec![0u64; slice.len()]
    } else {
        build_shot_delays(&cfg, slice.len())
    };

    let cache = mgr.cache.lock().await;
    let mut fire_list = Vec::new();
    let mut missing = 0usize;
    for (s, delay) in slice.iter().zip(delays.iter()) {
        if let Some(mfa) = cache.get(&s.token) {
            fire_list.push((
                s.lab.clone(),
                s.gid.clone(),
                s.token.clone(),
                mfa.token.clone(),
                mfa.cookie.clone(),
                *delay,
                s.sock_idx,
            ));
        } else {
            missing += 1;
        }
    }
    drop(cache);

    if missing > 0 {
        tracing::warn!("[{}] MFA eksik {missing} shot â€” atlandÄ±", cfg.name);
    }

    if fire_list.is_empty() {
        tracing::error!("[{}] FIRE iptal â€” MFA cache boÅŸ", cfg.name);
        if wave_limit.is_none() {
            *watch.fired.lock().await = false;
        }
        let _ = send_webhook(
            cfg.webhook,
            &format!("âšï¸ {} | {} | BOOST", EngineConfig::FLEET, cfg.name),
            &format!("MFA yok â€” 0 shot\nmissing_mfa={missing}"),
            0xED4245,
        )
        .await;
        return Ok(());
    }

    tracing::info!(
        "[{}] SCHEDULE {} TLS shot {}â€“{}ms{}",
        cfg.name,
        fire_list.len(),
        cfg.t0_ms,
        cfg.t1_ms,
        if cfg.tls_pool_per_lane > 0 {
            format!(" pool={}/lane", cfg.tls_pool_per_lane)
        } else {
            String::new()
        }
    );

    let pool = if cfg.tls_pool_per_lane > 0 {
        let per_lane = (cfg.tls_pool_per_lane as usize)
            .max(tls_pool::max_shots_per_lane(&fire_list).min(4));
        Some(tls_pool::build_pool(cfg.host, &fire_list, per_lane).await)
    } else {
        warm_tls(cfg.host, 2).await;
        None
    };

    let stats = scheduled_tls_fire(cfg.host, &fire_list, &vanity, t0, pool).await;

    tracing::info!(
        "[{}] shots_usedâ‰ˆ wave={:?} source={source} sent={}",
        cfg.name,
        wave_limit,
        fire_list.len()
    );

    let _ = send_webhook(
        cfg.webhook,
        &format!("ğŸš€ {} | {} | FIRE", EngineConfig::FLEET, cfg.name),
        &format!(
            "source=`{source}` vanity=`{vanity}` shots={} window={}â€“{}ms wave={:?}\ntrigger={:?}",
            fire_list.len(),
            cfg.t0_ms,
            cfg.t1_ms,
            wave_limit,
            cfg.trigger
        ),
        0x5865F2,
    )
    .await;

    let lane_order: Vec<String> = fire_list.iter().fold(Vec::new(), |mut acc, (lab, _, _, _, _, _, _)| {
        if !acc.contains(lab) {
            acc.push(lab.clone());
        }
        acc
    });
    let total_planned = fire_list.len() + missing;

    let icon = if stats.c200 > 0 || stats.c400 > 0 {
        "âœ…"
    } else {
        "âšï¸"
    };
    tracing::info!(
        "[{}] WAVE {} sent={} 200={} 400={} 403={} 429={} 500={} pair={} cf={} err={}",
        cfg.name,
        icon,
        stats.sent,
        stats.c200,
        stats.c400,
        stats.c403,
        stats.c429,
        stats.c500,
        stats.c_pair,
        stats.c_cf,
        stats.c_err
    );
    tracing::info!("[{}] --- token breakdown ---", cfg.name);
    for block in stats.format_lane_report(&lane_order).split("\n\n") {
        for line in block.lines() {
            tracing::info!("[{}]   {line}", cfg.name);
        }
    }

    let breakdown = stats.format_lane_report(&lane_order);
    let first_s = stats
        .first_rsp_ms
        .map(|m| format!("{m}ms"))
        .unwrap_or_else(|| "â€”".into());
    let last_s = stats
        .last_rsp_ms
        .map(|m| format!("{m}ms"))
        .unwrap_or_else(|| "â€”".into());
    let ok200_s = stats
        .first_200_ms
        .map(|m| format!("{m}ms"))
        .unwrap_or_else(|| "yok".into());
    let desc = format!(
        "BOOST â†’ **{}** ({source})\nPATCH **{}/{}** TLS{}\n200={} 400={} pair={} 403={} 429={} 500={} cf={} err={}\nmissing_mfa={}\nwindow={}â€“{}ms\n\nilk dÃ¶nen response : {}\nson dÃ¶nen response : {}\n200x varsa eÄŸer dÃ¶nen response : {}\n\n**Token Ã¶zeti**\n{}",
        cfg.name,
        stats.sent,
        total_planned,
        if cfg.tls_pool_per_lane > 0 {
            format!(" (pool {}/lane)", cfg.tls_pool_per_lane)
        } else {
            String::new()
        },
        stats.c200,
        stats.c400,
        stats.c_pair,
        stats.c403,
        stats.c429,
        stats.c500,
        stats.c_cf,
        stats.c_err,
        missing,
        cfg.t0_ms,
        cfg.t1_ms,
        first_s,
        last_s,
        ok200_s,
        breakdown,
    );
    let color = if stats.c200 > 0 {
        0x57F287
    } else if stats.c400 > 0 {
        0x57F287
    } else {
        0xFEE75C
    };
    let ping = if stats.c200 > 0 { Some("@everyone") } else { None };
    let _ = send_webhook_with_content(
        cfg.webhook,
        &format!("{icon} {} | {} | BOOST", EngineConfig::FLEET, cfg.name),
        &desc,
        color,
        ping,
    )
    .await;

    tokio::time::sleep(Duration::from_millis(cfg.t1_ms + 6000)).await;
    Ok(())
}