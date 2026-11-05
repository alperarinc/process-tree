fn main() {
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() == 3 && args[1] == "--helper" {
        // Never fall through to the GUI: it must not run as root.
        let code = match procexp::helper::run_server(std::path::Path::new(&args[2])) {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("procexp helper: {e}");
                1
            }
        };
        std::process::exit(code);
    }
    if let Err(e) = procexp::ui::run() {
        eprintln!("procexp: {e}");
        std::process::exit(1);
    }
}
