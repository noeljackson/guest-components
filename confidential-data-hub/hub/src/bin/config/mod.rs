// Copyright (c) 2026 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::env;

use anyhow::{Context, Result};
use confidential_data_hub::CdhConfig;
use tracing::info;

const CDH_DEFAULT_IMAGE_AUTHENTICATED_REGISTRY_CREDENTIALS: &str =
    "CDH_DEFAULT_IMAGE_AUTHENTICATED_REGISTRY_CREDENTIALS";

pub fn read_config(config_path: Option<String>) -> Result<(CdhConfig, String)> {
    let (mut config, config_log, image_from_file) = match config_path {
        Some(config_path) => {
            let config = CdhConfig::from_file(&config_path[..])
                .with_context(|| format!("failed to read config file {config_path}"))?;
            let image_from_file = CdhConfig::file_has_image_table(&config_path[..])
                .with_context(|| format!("failed to read config file {config_path}"))?;
            let log = format!("Using config file: {config_path}");
            (config, log, image_from_file)
        }
        None => {
            let log = "No CDH config path specified. Using default configuration.".to_string();
            let config = CdhConfig::default_with_kernel_cmdline()
                .with_context(|| "failed to read default configuration".to_string())?;
            (config, log, false)
        }
    };

    // With an `[image]` table, the image configuration is that table alone:
    // in a confidential guest it is the measured one, so nothing outside it
    // may change where pulls get their login (Codewire fork, codewire#4000).
    if image_from_file {
        if env::var(CDH_DEFAULT_IMAGE_AUTHENTICATED_REGISTRY_CREDENTIALS).is_ok() {
            info!("Ignoring {CDH_DEFAULT_IMAGE_AUTHENTICATED_REGISTRY_CREDENTIALS}: the config file has an [image] table");
        }
    } else if let std::result::Result::Ok(env) =
        env::var(CDH_DEFAULT_IMAGE_AUTHENTICATED_REGISTRY_CREDENTIALS)
    {
        info!("Read authenticated registry credentials URI from env: {env}");
        config.image.authenticated_registry_credentials_uri = Some(env);
    }

    config.extend_credentials_from_kernel_cmdline()?;

    Ok((config, config_log))
}

#[cfg(test)]
mod tests {
    use std::{env, io::Write};

    use serial_test::serial;

    use crate::config::read_config;

    fn config_file(config: &str) -> tempfile::NamedTempFile {
        let mut file = tempfile::Builder::new()
            .append(true)
            .suffix(".toml")
            .tempfile()
            .unwrap();
        file.write_all(config.as_bytes()).unwrap();
        file
    }

    #[test]
    #[serial]
    fn an_image_table_is_not_overridden_by_env() {
        let file = config_file(
            r#"
[kbc]
name = "offline_fs_kbc"

[image]
authenticated_registry_credentials_uri = "kbs:///default/auth/1"
        "#,
        );
        let config_path = file.path().to_str().unwrap().to_string();
        let (config, _) = read_config(Some(config_path.clone())).expect("Must be successful");
        assert_eq!(
            config.image.authenticated_registry_credentials_uri,
            Some("kbs:///default/auth/1".into())
        );

        env::set_var(
            "CDH_DEFAULT_IMAGE_AUTHENTICATED_REGISTRY_CREDENTIALS",
            "file:///test",
        );
        let (config, _) = read_config(Some(config_path)).unwrap();
        env::remove_var("CDH_DEFAULT_IMAGE_AUTHENTICATED_REGISTRY_CREDENTIALS");
        assert_eq!(
            config.image.authenticated_registry_credentials_uri,
            Some("kbs:///default/auth/1".into())
        );
    }

    #[test]
    #[serial]
    fn without_an_image_table_env_sets_the_login() {
        let file = config_file(
            r#"
[kbc]
name = "offline_fs_kbc"
        "#,
        );
        let config_path = file.path().to_str().unwrap().to_string();
        env::set_var(
            "CDH_DEFAULT_IMAGE_AUTHENTICATED_REGISTRY_CREDENTIALS",
            "file:///test",
        );
        let (config, _) = read_config(Some(config_path)).unwrap();
        env::remove_var("CDH_DEFAULT_IMAGE_AUTHENTICATED_REGISTRY_CREDENTIALS");
        assert_eq!(
            config.image.authenticated_registry_credentials_uri,
            Some("file:///test".to_string())
        );
    }
}
