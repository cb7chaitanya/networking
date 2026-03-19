use anyhow::Result;
use dns_resolver::dns::RecordData;
use dns_resolver::{DnsResolver, RecordType, TraceResponseType};
use std::env;

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: {} <domain> [record_type] [--trace]", args[0]);
        eprintln!("Example: {} example.com A", args[0]);
        eprintln!("Example: {} example.com A --trace", args[0]);
        std::process::exit(1);
    }

    let domain = &args[1];
    let mut record_type = RecordType::A;
    let mut trace_mode = false;

    for arg in &args[2..] {
        match arg.as_str() {
            "--trace" => trace_mode = true,
            _ => {
                if let Ok(rt) = arg.parse() {
                    record_type = rt;
                }
            }
        }
    }

    let mut resolver = DnsResolver::new();

    if trace_mode {
        println!("; <<>> DNS Trace <<>> {}", domain);
        println!(";;");
        println!(";;");

        let trace = resolver.resolve_trace(domain, record_type);

        for step in &trace.steps {
            let indent = "  ".repeat(step.depth as usize);
            let server = &step.server;
            let query = &step.query;

            match step.response_type {
                TraceResponseType::Referral => {
                    if step.depth == 0 {
                        println!(
                            ".                           518111  IN      NS      {}",
                            server
                        );
                    }
                    if let Some(ns) = step
                        .records
                        .iter()
                        .find(|r| r.record_type == RecordType::NS)
                    {
                        if let RecordData::NS(ns_name) = &ns.data {
                            println!("{};; Received from {}#53 in 1 ms", indent, server);
                            println!("{};; --- referral to {} ---", indent, ns_name);
                        }
                    }
                }
                TraceResponseType::Answer => {
                    println!("{}", indent);
                    for record in &trace.final_records {
                        println!("{}{}", indent, record);
                    }
                    println!("{};; Received from {}#53", indent, server);
                }
                TraceResponseType::CnameChain => {
                    if let Some(cname) = step
                        .records
                        .iter()
                        .find(|r| r.record_type == RecordType::CNAME)
                    {
                        if let RecordData::CNAME(target) = &cname.data {
                            println!(
                                "{}{}          300     IN      CNAME   {}",
                                indent, query, target
                            );
                        }
                    }
                }
                TraceResponseType::NxDomain => {
                    println!("{};; NXDOMAIN from {}#53", indent, server);
                }
                TraceResponseType::ServFail | TraceResponseType::Timeout => {
                    println!("{};; {:?} from {}#53", indent, step.response_type, server);
                }
            }
        }

        if trace.error.is_some() {
            eprintln!(";;");
            eprintln!(";;");
            eprintln!(";; DNS error occurred");
        }

        std::process::exit(if trace.error.is_some() { 1 } else { 0 });
    }

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
