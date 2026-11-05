fn main() {
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() == 3 && args[1] == "--helper" {
        if let Err(e) = procexp::helper::run_server(std::path::Path::new(&args[2])) {
            eprintln!("procexp helper: {e}");
            std::process::exit(1);
        }
    }
    // GUI: Task 10
}
