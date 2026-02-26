use anyhow::Result;
use dns_resolver::{DnsResolver, RecordType};
use std::env;

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: {} <domain> [record_type]", args[0]);
        eprintln!("Example: {} example.com A", args[0]);
        std::process::exit(1);
    }

    let domain = &args[1];
    let record_type = if args.len() >= 3 {
        args[2].parse().unwrap_or(RecordType::A)
    } else {
        RecordType::A
    };

    let mut resolver = DnsResolver::new();
    match resolver.resolve(domain, record_type) {
        Ok(records) => {
            for record in records {
                println!("{}", record);
            }
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }

    Ok(())
}
