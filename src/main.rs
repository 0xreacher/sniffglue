mod cli;
mod fmt;

use crate::cli::Args;
use clap::{CommandFactory, Parser};
use env_logger::Env;
use sniffglue::centrifuge;
use sniffglue::errors::*;
use sniffglue::link::DataLink;
use sniffglue::sandbox;
use sniffglue::sniff;
use sniffglue::structs::raw::Raw;
use std::io::{self, IsTerminal, stdout};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;

fn main() -> Result<()> {
    env_logger::init_from_env(Env::default().default_filter_or("sniffglue=warn"));

    let mut args = Args::parse();

    if let Some(shell) = args.gen_completions {
        clap_complete::generate(shell, &mut Args::command(), "sniffglue", &mut stdout());
        return Ok(());
    }

    sandbox::activate_stage1(args.insecure_disable_seccomp)
        .context("Failed to init sandbox stage1")?;

    let device = if let Some(dev) = args.device.take() {
        dev
    } else {
        sniff::default_interface().context("Failed to find default interface")?
    };

    let layout = if args.json {
        fmt::Layout::Json
    } else if args.debugging {
        fmt::Layout::Debugging
    } else {
        fmt::Layout::Compact
    };

    let colors = io::stdout().is_terminal();
    let config = fmt::Config::new(layout, args.verbose, colors);

    
    let filter = config.filter();

    let is_file_read = args.read;

    let cap = if is_file_read {
        if args.threads.is_none() {
            debug!("Setting thread default to 1 due to -r");
            args.threads = Some(1);
        }
        let cap = sniff::open_file(&device)?;
        eprintln!("Reading from file: {:?}", device);
        cap
    } else {
        let cap = sniff::open(
            &device,
            &sniff::Config {
                promisc: args.promisc,
                immediate_mode: true,
            },
        )?;
        
        if args.threads.is_none() {
            args.threads = Some(1);
        }
        eprintln!(
            "Listening on device: {:?}, verbosity {}/4",
            device,
            filter.verbosity
        );
        cap
    };

    let threads = args.threads.unwrap_or(1);
    debug!("Using {} threads", threads);

    let datalink = DataLink::from_linktype(cap.datalink())?;

    
    let (tx, rx) = mpsc::sync_channel::<Raw>(256);
    let cap = Arc::new(Mutex::new(cap));

    
    let done = Arc::new(AtomicBool::new(false));

    let packet_count = Arc::new(AtomicU64::new(0));

    sandbox::activate_stage2(args.insecure_disable_seccomp)
        .context("Failed to init sandbox stage2")?;

    let mut handles = Vec::with_capacity(threads);

    for _ in 0..threads {
        let cap = cap.clone();
        let datalink = datalink.clone();
        let filter = filter.clone();
        let tx = tx.clone();
        let done = done.clone();
        let packet_count = packet_count.clone();

        let handle = thread::spawn(move || {
            loop {
                if done.load(Ordering::Relaxed) {
                    break;
                }

                let packet = {
                    let mut cap = cap.lock().unwrap();
                    cap.next_pkt()
                };

                match packet {
                    Ok(Some(packet)) => {
                        let parsed = centrifuge::parse(&datalink, &packet.data);
                        if filter.matches(&parsed) {
                            packet_count.fetch_add(1, Ordering::Relaxed);
                            if tx.send(parsed).is_err() {
                                debug!("Receiver dropped, shutting down worker");
                                break;
                            }
                        }
                    }
                    Ok(None) => {
                        debug!("EOF, shutting down reader thread");
                        done.store(true, Ordering::Relaxed);
                        break;
                    }
                    Err(e) => {
                        debug!("Read error: {}, shutting down reader thread", e);
                        done.store(true, Ordering::Relaxed);
                        break;
                    }
                }
            }
        });

        handles.push(handle);
    }

    
    drop(tx);

    let format = config.format();
    for packet in rx.iter() {
        format.print(packet);
    }

    for handle in handles {
        let _ = handle.join();
    }

    if is_file_read {
        let count = packet_count.load(Ordering::Relaxed);
        eprintln!("Done. {} packet(s) matched.", count);
    }

    Ok(())
}
