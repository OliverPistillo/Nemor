use crate::model::{ForegroundState, ProcessCategory, ProcessClassification};
use collector::ProcessSample;
use common::ClassificationConfig;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::path::Path;

const IDENTITY_FORMAT_VERSION: &str = "nemor-process-identity-v2";
const CRITICAL: &[&str] = &[
    "init",
    "systemd",
    "dbus-daemon",
    "networkmanager",
    "pipewire",
    "wireplumber",
    "kwin_wayland",
    "gnome-shell",
    "sddm",
    "gdm",
    "gamescope",
    "easyanticheat",
    "easyanticheat_eos",
    "battleye",
    "beservice_x64",
];
const SYSTEM: &[&str] = &["systemd-journald", "systemd-logind", "udevd", "kworker"];
const BACKGROUND: &[&str] = &["tracker-miner-fs-3", "baloo_file", "updatedb"];

pub(crate) fn classify_all(
    samples: &[ProcessSample],
    config: &ClassificationConfig,
) -> Vec<ProcessClassification> {
    let names = samples
        .iter()
        .map(|sample| (sample.pid, normalized_name(sample)))
        .collect::<HashMap<_, _>>();
    let parents = samples
        .iter()
        .filter_map(|sample| sample.parent_pid.map(|parent| (sample.pid, parent)))
        .collect::<HashMap<_, _>>();
    samples
        .iter()
        .map(|sample| classify_one(sample, config, &names, &parents))
        .collect()
}

fn classify_one(
    sample: &ProcessSample,
    config: &ClassificationConfig,
    names: &HashMap<u32, String>,
    parents: &HashMap<u32, u32>,
) -> ProcessClassification {
    let name = normalized_name(sample);
    let ancestors = ancestor_names(sample.pid, names, parents);
    let known_identity = !name.is_empty();
    let configured_critical = contains_name(&config.critical_executables, &name);
    let configured_protected = contains_name(&config.protected_executables, &name);
    let critical = configured_critical || CRITICAL.contains(&name.as_str());
    let browser = is_browser(&name);
    let development = is_development(&name);
    let virtualization = is_virtualization(&name);
    let background = BACKGROUND.contains(&name.as_str());
    let steam_context = ancestors.iter().any(|value| is_steam(value));
    let gamescope_context = ancestors.iter().any(|value| value == "gamescope");
    let cgroup = sample
        .cgroup_path
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let steam_app_cgroup = cgroup.contains("steam_app_")
        || (cgroup.contains("/app-") && cgroup.contains("steam") && cgroup.contains(".scope"));
    let configured_game = contains_name(&config.game_executables, &name);
    let proton_or_wine = is_proton_or_wine(&name);

    let mut game_score: f64 = 0.0;
    let mut reasons = Vec::new();
    if configured_game {
        game_score = game_score.max(0.95);
        reasons.push("configured_game_executable".to_owned());
    }
    if steam_app_cgroup && !browser {
        game_score += 0.65;
        reasons.push("steam_app_cgroup".to_owned());
    }
    if steam_context && !browser && !is_steam_helper(&name) {
        game_score += 0.20;
        reasons.push("steam_ancestry".to_owned());
    }
    if proton_or_wine && steam_app_cgroup {
        game_score += 0.20;
        reasons.push("proton_wine_with_steam_context".to_owned());
    }
    if gamescope_context && !browser && !development && !is_known_helper(&name) {
        game_score += 0.80;
        reasons.push("gamescope_ancestry".to_owned());
    }
    game_score = game_score.min(1.0);
    let is_game = known_identity && game_score >= config.minimum_confidence;

    let (mut category, confidence) = if !known_identity {
        (ProcessCategory::Unknown, 0.0)
    } else if critical {
        (ProcessCategory::Critical, 0.98)
    } else if is_game {
        (ProcessCategory::Game, game_score)
    } else if browser {
        (ProcessCategory::Browser, 0.90)
    } else if development {
        (ProcessCategory::Development, 0.88)
    } else if virtualization {
        (ProcessCategory::Virtualization, 0.90)
    } else if background {
        (ProcessCategory::Background, 0.85)
    } else if SYSTEM.contains(&name.as_str()) || name.starts_with("kworker") {
        (ProcessCategory::System, 0.90)
    } else if is_desktop(&name) {
        (ProcessCategory::Desktop, 0.85)
    } else {
        (ProcessCategory::Unknown, 0.25)
    };
    if !critical && confidence < config.minimum_confidence {
        category = ProcessCategory::Unknown;
        reasons.push("below_minimum_process_confidence".to_owned());
    }

    let (foreground, foreground_confidence) =
        foreground_state(sample, gamescope_context && is_game);
    let protected_game = is_game;
    let protected = !known_identity
        || category == ProcessCategory::Unknown
        || critical
        || protected_game
        || configured_protected
        || foreground == ForegroundState::Foreground;
    if !known_identity {
        reasons.push("unknown_identity_protected".to_owned());
    }
    if critical {
        reasons.push("critical_process_protected".to_owned());
    }
    if configured_protected {
        reasons.push("configured_process_protected".to_owned());
    }
    if foreground == ForegroundState::Foreground {
        reasons.push("foreground_process_protected".to_owned());
    }
    if protected_game {
        reasons.push("game_process_protected".to_owned());
    }
    if reasons.is_empty() {
        reasons.push(format!("category_{category}"));
    }
    let cold_candidate = category == ProcessCategory::Background
        && foreground == ForegroundState::Background
        && confidence >= config.minimum_confidence
        && !protected
        && !is_game
        && !critical;

    let (persistent_name, command_signature) = stable_identity(sample, &name);
    ProcessClassification {
        sample: sample.clone(),
        executable: persistent_name.clone(),
        command_signature,
        application_name: known_identity.then_some(persistent_name),
        category,
        is_game,
        is_critical: critical,
        protected,
        protected_game,
        cold_candidate,
        foreground,
        foreground_confidence,
        confidence,
        reasons,
    }
}

fn stable_identity(sample: &ProcessSample, fallback_name: &str) -> (String, String) {
    let normalized_path = sample
        .executable
        .as_deref()
        .and_then(normalize_linux_executable_path);
    let basename = normalized_path
        .as_deref()
        .and_then(|path| path.rsplit('/').next())
        .filter(|value| !value.is_empty())
        .unwrap_or(fallback_name)
        .to_ascii_lowercase();
    let basename = if basename.is_empty() {
        "unknown".to_owned()
    } else {
        basename
    };
    let (display, kind, identity) = match normalized_path {
        Some(path) => {
            let display = if is_safe_system_path(&path) {
                path.clone()
            } else {
                format!("private:{basename}")
            };
            (display, "path", path)
        }
        None => (basename.clone(), "basename", basename),
    };
    let representation = format!("{IDENTITY_FORMAT_VERSION}\0{kind}\0{identity}");
    (
        display,
        hex::encode(Sha256::digest(representation.as_bytes())),
    )
}

fn normalize_linux_executable_path(raw: &str) -> Option<String> {
    let raw = raw.trim().trim_end_matches(" (deleted)");
    if !raw.starts_with('/') || raw.contains('\0') {
        return None;
    }
    let mut parts = Vec::new();
    for part in raw.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            value => parts.push(value),
        }
    }
    (!parts.is_empty()).then(|| format!("/{}", parts.join("/")))
}

fn is_safe_system_path(path: &str) -> bool {
    ["/usr/", "/bin/", "/sbin/", "/opt/", "/nix/store/", "/snap/"]
        .iter()
        .any(|prefix| path.starts_with(prefix))
}

fn normalized_name(sample: &ProcessSample) -> String {
    sample
        .executable
        .as_deref()
        .and_then(|value| Path::new(value).file_name())
        .and_then(|value| value.to_str())
        .or(sample.executable_name.as_deref())
        .unwrap_or_default()
        .trim_end_matches(" (deleted)")
        .to_ascii_lowercase()
}

fn ancestor_names(
    pid: u32,
    names: &HashMap<u32, String>,
    parents: &HashMap<u32, u32>,
) -> HashSet<String> {
    let mut result = HashSet::new();
    let mut current = pid;
    let mut seen = HashSet::new();
    for _ in 0..16 {
        if !seen.insert(current) {
            break;
        }
        let Some(parent) = parents.get(&current).copied() else {
            break;
        };
        if let Some(name) = names.get(&parent) {
            result.insert(name.clone());
        }
        current = parent;
    }
    result
}

fn contains_name(values: &[String], name: &str) -> bool {
    values.iter().any(|value| value.eq_ignore_ascii_case(name))
}

fn is_browser(name: &str) -> bool {
    [
        "firefox",
        "chrome",
        "chromium",
        "google-chrome",
        "brave",
        "brave-browser",
        "vivaldi",
        "vivaldi-bin",
        "opera",
        "msedge",
    ]
    .iter()
    .any(|family| name == *family || name.starts_with(&format!("{family}-")))
}

fn is_development(name: &str) -> bool {
    matches!(
        name,
        "code"
            | "codium"
            | "rustc"
            | "cargo"
            | "gcc"
            | "g++"
            | "clang"
            | "clang++"
            | "cmake"
            | "ninja"
            | "rust-analyzer"
            | "clangd"
            | "gdb"
            | "lldb"
    ) || name.starts_with("idea")
        || name.starts_with("clion")
}

fn is_virtualization(name: &str) -> bool {
    name.starts_with("qemu-system") || matches!(name, "virtualboxvm" | "vmware-vmx" | "vmware")
}

fn is_desktop(name: &str) -> bool {
    matches!(
        name,
        "plasmashell" | "konsole" | "gnome-terminal-server" | "dolphin" | "nautilus"
    )
}

fn is_steam(name: &str) -> bool {
    matches!(name, "steam" | "steamwebhelper" | "steam-runtime")
}

fn is_steam_helper(name: &str) -> bool {
    matches!(
        name,
        "steam" | "steamwebhelper" | "steam-runtime" | "pressure-vessel"
    )
}

fn is_proton_or_wine(name: &str) -> bool {
    name.contains("proton") || name.starts_with("wine")
}

fn is_known_helper(name: &str) -> bool {
    is_steam_helper(name) || is_proton_or_wine(name) || name == "gamescope"
}

fn foreground_state(sample: &ProcessSample, gamescope_game: bool) -> (ForegroundState, f64) {
    if gamescope_game {
        return (ForegroundState::Foreground, 0.85);
    }
    match (
        sample.tty_nr,
        sample.process_group_id,
        sample.foreground_process_group_id,
    ) {
        (Some(tty), Some(group), Some(foreground)) if tty > 0 && foreground > 0 => {
            if group == foreground {
                (ForegroundState::Foreground, 0.98)
            } else {
                (ForegroundState::Background, 0.95)
            }
        }
        _ => (ForegroundState::Unknown, 0.0),
    }
}
