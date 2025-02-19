use {
    clap::Parser,
    color_eyre::eyre::{Context, Result},
    qapi::{qmp, Qmp},
    regex::Regex,
    std::{
        io::{BufRead, Write},
        os::unix::net::UnixStream,
        thread::sleep,
        time::{Duration, Instant},
    },
};

#[derive(Parser, Debug)]
struct Args {
    /// Path to the QMP socket
    #[arg(short, long)]
    socket: String,

    /// Sampling frequency (Hz)
    ///
    /// Each sample takes ~900us so any frequency over/around 1000Hz may not be accurate
    #[arg(short, long)]
    frequency: u32,
}

fn main() -> Result<()> {
    color_eyre::install()?;
    let args = Args::parse();

    let stream = UnixStream::connect(&args.socket)
        .wrap_err_with(|| format!("Failed to connect to socket {:?}", &args.socket))?;

    let mut qmp = Qmp::from_stream(&stream);

    let _ = qmp.handshake().wrap_err("handshake failed")?;

    loop {
        let start = Instant::now();
        let rip = get_instruction_pointer(&mut qmp)?;
        let end = Instant::now();

        println!("RIP: {rip:x}, took {}us", (end - start).as_micros());

        sleep(Duration::from_secs(1));
    }
}

fn get_instruction_pointer<S: BufRead + Write>(qmp: &mut Qmp<S>) -> Result<u64> {
    let re = Regex::new(r"RIP=([0-9a-f]+)").unwrap();

    let registers = qmp.execute(&qmp::human_monitor_command {
        cpu_index: None,
        command_line: "info registers".into(),
    })?;

    let caps = re
        .captures(&registers)
        .ok_or(color_eyre::eyre::eyre!("Regex failed to find matches"))?;

    Ok(u64::from_str_radix(&caps[1], 16)?)
}
