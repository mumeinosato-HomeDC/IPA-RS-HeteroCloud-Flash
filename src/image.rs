use std::time::Duration;

use oci_client::{
    Client, Reference,
    client::{Certificate, CertificateEncoding, ClientConfig},
    config::ConfigFile,
    manifest::{OciImageManifest, OciManifest},
    secrets::RegistryAuth,
};
use thiserror::Error;

pub const GIB_BYTES: u64 = 1024 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImageInspection {
    pub resolved_image: String,
    pub image_size_bytes: u64,
    pub writable_storage_bytes: u64,
    pub image_entrypoint: Vec<String>,
    pub image_cmd: Vec<String>,
    pub architecture: String,
}

#[derive(Clone)]
pub struct ImageInspector {
    client: Client,
    registry_auth: Option<ScopedRegistryAuth>,
}

#[derive(Clone)]
struct ScopedRegistryAuth {
    registry: String,
    auth: RegistryAuth,
}

impl ImageInspector {
    #[must_use]
    pub fn new() -> Self {
        Self::with_root_certificates(&[])
    }

    /// Like [`Self::new`], additionally trusting PEM CA certificates (for example a
    /// private registry CA) on top of the default roots.
    #[must_use]
    pub fn with_root_certificates(pem_bundles: &[Vec<u8>]) -> Self {
        let config = ClientConfig {
            connect_timeout: Some(Duration::from_secs(5)),
            read_timeout: Some(Duration::from_secs(15)),
            user_agent: concat!("heterocloud-flash/", env!("CARGO_PKG_VERSION")),
            extra_root_certificates: pem_bundles
                .iter()
                .map(|pem| Certificate {
                    encoding: CertificateEncoding::Pem,
                    data: pem.clone(),
                })
                .collect(),
            ..ClientConfig::default()
        };
        Self {
            client: Client::new(config),
            registry_auth: None,
        }
    }

    #[must_use]
    pub fn with_basic_auth(registry: String, username: String, password: String) -> Self {
        Self::with_basic_auth_and_roots(registry, username, password, &[])
    }

    #[must_use]
    pub fn with_basic_auth_and_roots(
        registry: String,
        username: String,
        password: String,
        pem_bundles: &[Vec<u8>],
    ) -> Self {
        let mut inspector = Self::with_root_certificates(pem_bundles);
        inspector.registry_auth = Some(ScopedRegistryAuth {
            registry,
            auth: RegistryAuth::Basic(username, password),
        });
        inspector
    }

    pub async fn inspect(
        &self,
        image: &str,
        disk_budget_bytes: u64,
    ) -> Result<ImageInspection, ImageInspectionError> {
        let reference = Reference::try_from(image.to_owned()).map_err(|error| {
            ImageInspectionError::InvalidReference {
                image: image.to_owned(),
                reason: error.to_string(),
            }
        })?;
        let auth = self.auth_for(&reference);
        let (manifest, digest) =
            self.client
                .pull_manifest(&reference, &auth)
                .await
                .map_err(|error| ImageInspectionError::Registry {
                    image: image.to_owned(),
                    reason: error.to_string(),
                })?;

        let image_size_bytes = match manifest {
            OciManifest::Image(manifest) => manifest_size_bytes(&manifest)?,
            OciManifest::ImageIndex(index) => {
                let linux_entries = index
                    .manifests
                    .into_iter()
                    .filter(|entry| {
                        entry.platform.as_ref().is_some_and(|platform| {
                            platform.os.to_string().eq_ignore_ascii_case("linux")
                        })
                    })
                    .collect::<Vec<_>>();
                if linux_entries.is_empty() {
                    return Err(ImageInspectionError::NoLinuxManifest {
                        image: image.to_owned(),
                    });
                }

                let mut largest = 0_u64;
                for entry in linux_entries {
                    let platform_reference = reference.clone_with_digest(entry.digest);
                    let (platform_manifest, _) = self
                        .client
                        .pull_manifest(&platform_reference, &auth)
                        .await
                        .map_err(|error| ImageInspectionError::Registry {
                            image: image.to_owned(),
                            reason: error.to_string(),
                        })?;
                    let OciManifest::Image(platform_manifest) = platform_manifest else {
                        return Err(ImageInspectionError::NestedImageIndex {
                            image: image.to_owned(),
                        });
                    };
                    largest = largest.max(manifest_size_bytes(&platform_manifest)?);
                }
                largest
            }
        };
        let writable_storage_bytes = writable_storage_bytes(image_size_bytes, disk_budget_bytes)?;
        let resolved_reference = reference.clone_with_digest(digest);
        let (selected_manifest, _) = self
            .client
            .pull_image_manifest(&resolved_reference, &auth)
            .await
            .map_err(|error| ImageInspectionError::Registry {
                image: image.to_owned(),
                reason: error.to_string(),
            })?;
        if selected_manifest.config.size < 0 || selected_manifest.config.size > 1_048_576 {
            return Err(ImageInspectionError::InvalidImageConfig);
        }
        let mut config_bytes = Vec::new();
        self.client
            .pull_blob(
                &resolved_reference,
                &selected_manifest.config,
                &mut config_bytes,
            )
            .await
            .map_err(|error| ImageInspectionError::Registry {
                image: image.to_owned(),
                reason: error.to_string(),
            })?;
        let config: ConfigFile = serde_json::from_slice(&config_bytes)
            .map_err(|_| ImageInspectionError::InvalidImageConfig)?;
        if !config.os.to_string().eq_ignore_ascii_case("linux") {
            return Err(ImageInspectionError::UnsupportedPlatform);
        }
        let (image_entrypoint, image_cmd) = config.config.map_or_else(
            || (Vec::new(), Vec::new()),
            |runtime| {
                (
                    runtime.entrypoint.unwrap_or_default(),
                    runtime.cmd.unwrap_or_default(),
                )
            },
        );

        Ok(ImageInspection {
            resolved_image: resolved_reference.to_string(),
            image_size_bytes,
            writable_storage_bytes,
            image_entrypoint,
            image_cmd,
            architecture: config.architecture.to_string(),
        })
    }

    fn auth_for(&self, reference: &Reference) -> RegistryAuth {
        self.registry_auth
            .as_ref()
            .filter(|configured| {
                configured
                    .registry
                    .eq_ignore_ascii_case(reference.registry())
            })
            .map_or(RegistryAuth::Anonymous, |configured| {
                configured.auth.clone()
            })
    }
}

impl Default for ImageInspector {
    fn default() -> Self {
        Self::new()
    }
}

fn manifest_size_bytes(manifest: &OciImageManifest) -> Result<u64, ImageInspectionError> {
    std::iter::once(&manifest.config)
        .chain(manifest.layers.iter())
        .try_fold(0_u64, |total, descriptor| {
            let size = u64::try_from(descriptor.size).map_err(|_| {
                ImageInspectionError::InvalidDescriptorSize {
                    digest: descriptor.digest.clone(),
                    size: descriptor.size,
                }
            })?;
            total
                .checked_add(size)
                .ok_or(ImageInspectionError::ImageSizeOverflow)
        })
}

fn writable_storage_bytes(
    image_size_bytes: u64,
    disk_budget_bytes: u64,
) -> Result<u64, ImageInspectionError> {
    if image_size_bytes >= disk_budget_bytes {
        return Err(ImageInspectionError::DiskLimitExceeded {
            image_size_bytes,
            disk_budget_bytes,
        });
    }
    Ok(disk_budget_bytes - image_size_bytes)
}

#[derive(Debug, Error)]
pub enum ImageInspectionError {
    #[error("invalid OCI image reference `{image}`: {reason}")]
    InvalidReference { image: String, reason: String },
    #[error("OCI registry inspection failed for `{image}`: {reason}")]
    Registry { image: String, reason: String },
    #[error("OCI image index for `{image}` has no Linux manifest")]
    NoLinuxManifest { image: String },
    #[error("OCI image index for `{image}` contains another image index")]
    NestedImageIndex { image: String },
    #[error("OCI descriptor {digest} has invalid size {size}")]
    InvalidDescriptorSize { digest: String, size: i64 },
    #[error("OCI image configuration is invalid or too large")]
    InvalidImageConfig,
    #[error("OCI image is not a Linux image")]
    UnsupportedPlatform,
    #[error("OCI image descriptor sizes overflow the supported range")]
    ImageSizeOverflow,
    #[error(
        "container image requires {image_size_bytes} bytes, which leaves no writable space in the configured {disk_budget_bytes}-byte disk limit"
    )]
    DiskLimitExceeded {
        image_size_bytes: u64,
        disk_budget_bytes: u64,
    },
}

impl ImageInspectionError {
    #[must_use]
    pub const fn retryable(&self) -> bool {
        matches!(self, Self::Registry { .. })
    }
}

#[cfg(test)]
mod tests {
    use oci_client::manifest::{OciDescriptor, OciImageManifest};

    use super::{GIB_BYTES, ImageInspectionError, manifest_size_bytes, writable_storage_bytes};

    fn descriptor(digest: &str, size: i64) -> OciDescriptor {
        OciDescriptor {
            digest: digest.into(),
            size,
            ..OciDescriptor::default()
        }
    }

    #[test]
    fn image_layers_are_charged_against_the_disk_budget() -> Result<(), Box<dyn std::error::Error>>
    {
        let manifest = OciImageManifest {
            config: descriptor("sha256:config", 100),
            layers: vec![
                descriptor("sha256:layer-1", 200),
                descriptor("sha256:layer-2", 300),
            ],
            ..OciImageManifest::default()
        };
        let image_size = manifest_size_bytes(&manifest)?;
        assert_eq!(image_size, 600);
        assert_eq!(
            writable_storage_bytes(image_size, GIB_BYTES)?,
            GIB_BYTES - 600
        );
        Ok(())
    }

    #[test]
    fn image_at_or_over_the_disk_budget_is_rejected() {
        assert!(matches!(
            writable_storage_bytes(GIB_BYTES, GIB_BYTES),
            Err(ImageInspectionError::DiskLimitExceeded { .. })
        ));
        assert!(matches!(
            writable_storage_bytes(GIB_BYTES + 1, GIB_BYTES),
            Err(ImageInspectionError::DiskLimitExceeded { .. })
        ));
    }
}
