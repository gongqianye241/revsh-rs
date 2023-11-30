use anyhow::Result;
use clap::{App, Arg};
use env_logger::Env;
use log::{error, info};
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;

use revsh::target::Target;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    let mut target = Target::new("127.0.0.1:2200".to_string());
    target.run().await?;

    Ok(())
}
