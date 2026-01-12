use serde::{Deserialize, Serialize};
use std::fs::File;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SecurityPolicy {
    pub revision: u64,
    pub blocked_domains: Vec<String>,
    pub blocked_ips: Vec<String>,
    // Panic button
    pub lockdown_mode: bool,
}

impl SecurityPolicy {
    pub fn default_allow() -> Self {
        Self {
            revision: 0,
            blocked_domains: vec![],
            blocked_ips: vec![],
            lockdown_mode: false,
        }
    }
}

pub fn expand_path(path: &str) -> String {
    if path.starts_with("~/")
        && let Some(home) = dirs::home_dir()
            // Convert PathBuf to string and replace the first "~"
            && let Some(home_str) = home.to_str()
    {
        return path.replacen("~", home_str, 1);
    }

    path.to_string()
}

pub async fn load_policy(raw_path: &str) -> SecurityPolicy {
    let path_string = expand_path(raw_path);
    let path = path_string.as_str();

    if path.starts_with("http://") || path.starts_with("https://") {
        match reqwest::get(path).await {
            Ok(resp) => match resp.json::<SecurityPolicy>().await {
                Ok(p) => {
                    log::info!("secexit policy (v{}) loaded from URL: {}", p.revision, path);
                    return p;
                }
                Err(e) => log::warn!("Failed to parse policy from URL {}: {}", path, e),
            },
            Err(e) => log::warn!("Failed to fetch policy from URL {}: {}", path, e),
        }
    } else {
        if let Ok(file) = File::open(path)
            && let Ok(p) = serde_json::from_reader::<_, SecurityPolicy>(file)
        {
            log::info!("secexit policy (v{}) loaded from: {}", p.revision, path);
            return p;
        }

        log::warn!("No policy found at {}.", path);
    }

    log::warn!("Defaulting to empty policy.");
    SecurityPolicy::default_allow()
}
