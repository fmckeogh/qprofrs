use {
    addr2line::{fallible_iterator::FallibleIterator, Loader},
    clap::Parser,
    clap_num::maybe_hex,
    color_eyre::eyre::{eyre, Context, Result},
    qapi::{
        futures::{QapiService, QmpStreamTokio},
        qmp,
    },
    regex::Regex,
    std::{
        collections::HashMap,
        time::{Duration, Instant},
    },
    tokio::{io::WriteHalf, net::UnixStream, signal::ctrl_c},
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
    frequency: u64,

    /// Path to executable
    #[arg(short, long)]
    executable: String,

    /// Executable base address/load offset
    #[arg(short, long, value_parser=maybe_hex::<u64>)]
    offset: u64,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    color_eyre::install()?;
    let args = Args::parse();

    let debug = addr2line::Loader::new(args.executable)
        .map_err(|e| eyre!("Failed to load DWARF info: {e:?}"))?;

    // connect to QMP socket
    let stream = qapi::futures::QmpStreamTokio::open_uds(&args.socket)
        .await
        .wrap_err_with(|| format!("Failed to connect to socket {:?}", &args.socket))?;

    // negotiate stream
    let stream = stream
        .negotiate()
        .await
        .wrap_err("Failed to negotiate stream")?;
    let (qmp, _handle) = stream.spawn_tokio();

    // function hit counters
    let mut map = HashMap::<String, u64>::new();

    tokio::select! {
        // should never terminate
        _ = run_loop(&debug, &qmp, args.frequency, args.offset, &mut map) => {
            Ok(())
        },
        // print map and terminate on exit
        _ = ctrl_c() => {
            eprintln!("exiting!");

            for (ident, count) in map {
                println!("{ident} {count}");
            }

            Ok(())
        },
    }
}

async fn run_loop(
    debug: &Loader,
    qmp: &QapiService<QmpStreamTokio<WriteHalf<UnixStream>>>,
    frequency: u64,
    offset: u64,
    map: &mut HashMap<String, u64>,
) -> Result<()> {
    // regex for extracting RIP out of `info registers` command output
    let re = Regex::new(r"RIP=([0-9a-f]+)").unwrap();

    // interval between samples
    let mut interval = tokio::time::interval(Duration::from_nanos(1_000_000_000 / frequency));

    loop {
        // interval not sleep, so no drift over time
        interval.tick().await;

        let start = Instant::now();

        // get all register values
        let registers = qmp
            .execute(&qmp::human_monitor_command {
                cpu_index: None,
                command_line: "info registers".into(),
            })
            .await?;

        // pull out RIP
        let caps = re
            .captures(&registers)
            .ok_or(eyre!("Regex failed to find matches"))?;

        // parse hex
        let rip = u64::from_str_radix(&caps[1], 16)?;

        // get frames
        let frames = debug.find_frames(rip - offset).unwrap();

        // build identifier from frames
        let ident = frames
            .map(|f| {
                Ok(f.function
                    .map(|name| name.demangle().unwrap().into_owned())
                    .unwrap_or("???".to_owned()))
            })
            .collect::<Vec<_>>()
            .unwrap()
            .join(";");

        // insert or increment in map
        map.entry(ident).and_modify(|e| *e += 1).or_insert(1);

        let end = Instant::now();

        eprintln!("RIP: {rip:x}, avg {}us", (end - start).as_micros());
    }
}
