use std::{collections::BTreeSet, env, fs, process::ExitCode};

use anyhow::{Context, Result};
use heterocloud_flash::image::ImageInspector;
use heterocloud_flash::reconcile::{
    AdminVolumeMounts, ControllerConfig, run_controller, validate_admin_volume_mounts,
    validate_public_domain,
};
use ipnet::IpNet;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> ExitCode {
    install_crypto_provider();
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(error = ?error, "flash-controller stopped");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<()> {
    let namespace =
        env::var("FLASH_WORKLOAD_NAMESPACE").context("FLASH_WORKLOAD_NAMESPACE is required")?;
    let helper_image = env::var("FLASH_HELPER_IMAGE").context("FLASH_HELPER_IMAGE is required")?;
    let registry_host = optional("FLASH_REGISTRY_HOST");
    let registry_username = optional("FLASH_REGISTRY_USERNAME");
    let registry_password_file = optional("FLASH_REGISTRY_PASSWORD_FILE");
    let registry_pull_secret = optional("FLASH_REGISTRY_PULL_SECRET");
    let persistent_storage_class = optional("FLASH_PERSISTENT_STORAGE_CLASS");
    let public_domain = optional("FLASH_PUBLIC_DOMAIN");
    if let Some(domain) = &public_domain {
        validate_public_domain(domain)?;
    }
    if let Some(endpoint) = optional("FLASH_WORKLOAD_IDENTITY_ENDPOINT") {
        let url = url::Url::parse(&endpoint).context("invalid workload identity endpoint")?;
        anyhow::ensure!(
            url.scheme() == "https"
                && url.host_str().is_some()
                && url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none(),
            "workload identity endpoint must be HTTPS without credentials/query/fragment"
        );
    }
    let admin_volume_mounts = optional("FLASH_ADMIN_VOLUME_MOUNTS_JSON")
        .map(|value| serde_json::from_str::<AdminVolumeMounts>(&value))
        .transpose()
        .context("FLASH_ADMIN_VOLUME_MOUNTS_JSON is invalid")?
        .unwrap_or_default();
    validate_admin_volume_mounts(&admin_volume_mounts)?;
    let additional_protected_networks = network_cidrs("FLASH_ADDITIONAL_PROTECTED_CIDRS_JSON")?;
    let dns_networks = network_cidrs("FLASH_DNS_CIDRS_JSON")?;
    let secret_manager_networks = network_cidrs("FLASH_SECRET_MANAGER_CIDRS_JSON")?;
    if dns_networks.is_empty() {
        anyhow::bail!("FLASH_DNS_CIDRS_JSON must contain at least one DNS service address");
    }
    let configured = [
        registry_host.is_some(),
        registry_username.is_some(),
        registry_password_file.is_some(),
        registry_pull_secret.is_some(),
    ];
    if configured.iter().any(|value| *value) && !configured.iter().all(|value| *value) {
        anyhow::bail!(
            "FLASH_REGISTRY_HOST, FLASH_REGISTRY_USERNAME, FLASH_REGISTRY_PASSWORD_FILE and FLASH_REGISTRY_PULL_SECRET must be configured together"
        );
    }
    let image_inspector = match (registry_host, registry_username, registry_password_file) {
        (Some(host), Some(username), Some(password_file)) => {
            if host.contains('/') || host.chars().any(char::is_whitespace) {
                anyhow::bail!("FLASH_REGISTRY_HOST must be a registry host without a URL scheme");
            }
            let password = fs::read_to_string(&password_file)
                .with_context(|| format!("read registry password from {password_file}"))?
                .trim_end_matches(['\r', '\n'])
                .to_owned();
            if username.is_empty() || password.is_empty() {
                anyhow::bail!("registry username and password must not be empty");
            }
            let roots = match optional("FLASH_REGISTRY_CA_FILE") {
                Some(path) => {
                    vec![fs::read(&path).with_context(|| format!("read registry CA from {path}"))?]
                }
                None => Vec::new(),
            };
            ImageInspector::with_basic_auth_and_roots(host, username, password, &roots)
        }
        (None, None, None) => ImageInspector::new(),
        _ => unreachable!("registry configuration completeness was checked"),
    };
    let client = kube::Client::try_default()
        .await
        .context("create Kubernetes client")?;
    let activator_namespace =
        env::var("FLASH_ACTIVATOR_NAMESPACE").context("FLASH_ACTIVATOR_NAMESPACE is required")?;
    let activator_service =
        env::var("FLASH_ACTIVATOR_SERVICE").context("FLASH_ACTIVATOR_SERVICE is required")?;
    let activator_port = env::var("FLASH_ACTIVATOR_PORT")
        .context("FLASH_ACTIVATOR_PORT is required")?
        .parse::<u16>()
        .context("FLASH_ACTIVATOR_PORT must be a TCP port")?;
    run_controller(
        client,
        image_inspector,
        ControllerConfig {
            namespace,
            helper_image,
            registry_pull_secret,
            persistent_storage_class,
            admin_volume_mounts,
            additional_protected_networks,
            dns_networks,
            secret_manager_networks,
            vpc_guard_networks: network_cidrs("FLASH_VPC_GUARD_CIDRS_JSON")?,
            public_domain,
            workload_identity_endpoint: optional("FLASH_WORKLOAD_IDENTITY_ENDPOINT"),
            activator_namespace,
            activator_service,
            activator_port,
        },
    )
    .await
}

fn network_cidrs(name: &str) -> Result<Vec<IpNet>> {
    let values = optional(name)
        .map(|value| serde_json::from_str::<Vec<String>>(&value))
        .transpose()
        .with_context(|| format!("{name} must be a JSON string array"))?
        .unwrap_or_default();
    let mut networks = BTreeSet::new();
    for value in values {
        let network = value
            .parse::<IpNet>()
            .with_context(|| format!("{name} contains invalid CIDR {value}"))?
            .trunc();
        if !networks.insert(network) {
            anyhow::bail!("{name} contains duplicate CIDR {network}");
        }
    }
    Ok(networks.into_iter().collect())
}

fn optional(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn install_crypto_provider() {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        let _result = rustls::crypto::ring::default_provider().install_default();
    }
}
