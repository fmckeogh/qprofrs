use {
    addr2line::{fallible_iterator::FallibleIterator, Loader},
    clap::Parser,
    clap_num::maybe_hex,
    color_eyre::eyre::{eyre, Context, Result},
    core::str,
    itertools::Itertools,
    qapi::{
        futures::{QapiService, QmpStreamTokio},
        qmp,
    },
    regex::Regex,
    std::time::{Duration, Instant},
    tokio::{io::WriteHalf, net::UnixStream, signal::ctrl_c},
};

#[derive(Debug)]
struct StackFrame {
    rbp: u64,
    rip: u64,
}

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

    let mut stacks = Vec::new();

    tokio::select! {
        // should never terminate
        _ = run_loop( &qmp, args.frequency,  &mut stacks) => {
            Ok(())
        },
        // print map and terminate on exit
        _ = ctrl_c() => {
            eprintln!("exiting!");
            print_stacks(&stacks, &debug, args.offset)?;
            Ok(())
        },
    }
}

async fn get_stack_frame(
    qmp: &QapiService<QmpStreamTokio<WriteHalf<UnixStream>>>,
    guest_ptr: u64,
) -> Result<StackFrame> {
    let dump = qmp
        .execute(&qmp::human_monitor_command {
            cpu_index: None,
            command_line: format!("x /2g {guest_ptr:#x}"),
        })
        .await?;
    let rbp = u64::from_str_radix(str::from_utf8(&dump.as_bytes()[0x14..0x24])?, 16)?;
    let rip = u64::from_str_radix(str::from_utf8(&dump.as_bytes()[0x27..0x37])?, 16)?;

    let frame = StackFrame { rbp, rip };

    Ok(frame)
}

async fn run_loop(
    qmp: &QapiService<QmpStreamTokio<WriteHalf<UnixStream>>>,
    frequency: u64,
    stacks: &mut Vec<Vec<u64>>,
) -> Result<()> {
    // regex for extracting registers out of `info registers` command output
    let rbp_regex = Regex::new(r"RBP=([0-9a-f]+)").unwrap();

    // interval between samples
    let mut interval = tokio::time::interval(Duration::from_nanos(1_000_000_000 / frequency));

    loop {
        // interval not sleep, so no drift over time
        interval.tick().await;

        let start = Instant::now();

        qmp.execute(&qmp::human_monitor_command {
            cpu_index: None,
            command_line: "stop".into(),
        })
        .await?;

        // get all register values
        let registers = qmp
            .execute(&qmp::human_monitor_command {
                cpu_index: None,
                command_line: "info registers".into(),
            })
            .await?;

        let rbp = {
            let caps = rbp_regex
                .captures(&registers)
                .ok_or(eyre!("Regex failed to find matches"))?;

            // parse hex
            u64::from_str_radix(&caps[1], 16)?
        };

        let mut stack = vec![];
        let mut current_bp = rbp;

        while current_bp != 0 {
            let frame = get_stack_frame(qmp, current_bp).await?;
            stack.push(frame.rip);
            current_bp = frame.rbp;
        }

        let depth = stack.len();

        stacks.push(stack);

        qmp.execute(&qmp::human_monitor_command {
            cpu_index: None,
            command_line: "cont".into(),
        })
        .await?;

        let end = Instant::now();

        eprintln!("depth: {depth}, avg {}us", (end - start).as_micros());
    }
}

fn print_stacks(stacks: &Vec<Vec<u64>>, debug: &Loader, offset: u64) -> Result<()> {
    stacks
        .iter()
        .map(|stack| {
            stack
                .iter()
                .rev()
                .map(|rip| {
                    debug
                        .find_frames(rip - offset)
                        .expect("failed to find frames")
                        .last()
                        .expect("failed to get last element of iterator")
                        .map(|frame| {
                            frame
                                .function
                                .expect("function field in frame was None")
                                .demangle()
                                .expect("failed to demangle")
                                .into_owned()
                        })
                        .unwrap_or("???".into())
                })
                .join(";")
        })
        .counts()
        .into_iter()
        .for_each(|(ident, count)| println!("{ident} {count}"));

    Ok(())
}
