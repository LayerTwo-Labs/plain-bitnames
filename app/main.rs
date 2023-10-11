use std::sync::mpsc;

use clap::Parser as _;

mod app;
mod cli;
mod gui;
mod rpc;

fn main() -> anyhow::Result<()> {
    let cli = cli::Cli::parse();
    let config = cli.get_config()?;
    let app = app::App::new(&config)?;

    if config.headless {
        // wait for ctrlc signal
        let (tx, rx) = mpsc::channel();
        ctrlc::set_handler(move || {
            tx.send(()).unwrap();
        })
        .expect("Error setting Ctrl-C handler");
        rx.recv().unwrap();
        println!("Received Ctrl-C signal, exiting...");
    } else {
        let native_options = eframe::NativeOptions::default();
        eframe::run_native(
            "Plain Bitnames",
            native_options,
            Box::new(|cc| Box::new(gui::EguiApp::new(app, cc))),
        )
        .expect("failed to launch egui app");
    }
    Ok(())
}
