use chrono::NaiveDateTime;
use clap::Parser;
use libpcap_tools::{Duration, Packet};
use mysql::prelude::{FromRow, Queryable};
use mysql::{FromRowError, Pool, Row};
use pcap_parser::data::PacketData;
use pcap_parser::Linktype;
use pcap_rewrite::rewriter::{FileFormat, Rewriter};
use std::fs;
use std::io;
use tracing::Level;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
struct Args {
    #[arg(long)]
    sql: String,

    #[arg(long)]
    out: String,
}

struct PacketRecord {
    ts: Duration,
    link_type: Linktype,
    length: u32,
    packet_data: Vec<u8>,
}

impl FromRow for PacketRecord {
    fn from_row_opt(mut row: Row) -> Result<Self, FromRowError>
    where
        Self: Sized,
    {
        fn take_string(row: &mut Row, i: usize) -> String {
            row.take::<Vec<u8>, usize>(i)
                .and_then(|x| String::from_utf8(x).ok())
                .unwrap_or_else(|| panic!("Mysql text protocol returns not UTF-8 string bytes?"))
        }

        // ts
        let ts = take_string(&mut row, 0);
        let ts = NaiveDateTime::parse_from_str(&ts, "%Y-%m-%d %H:%M:%S%.6f")
            .unwrap_or_else(|e| panic!("Illegal timestamp date: '{ts}', error: {e}"))
            .and_utc()
            .timestamp_micros();
        let ts = Duration::new((ts / 1_000_000) as u32, (ts % 1_000_000) as u32);

        // link_type
        let link_type = take_string(&mut row, 1);
        let link_type = Linktype(
            link_type
                .parse()
                .unwrap_or_else(|_| panic!("Illegal link type: '{link_type}'")),
        );

        // length
        let length = take_string(&mut row, 2);
        let length = length
            .parse::<u32>()
            .unwrap_or_else(|_| panic!("Illegal length: '{length}'"));

        // packet_data
        let packet_data = row
            .take::<Vec<u8>, usize>(3)
            .unwrap_or_else(|| panic!("Missing packet data"));

        Ok(PacketRecord {
            ts,
            link_type,
            length,
            packet_data,
        })
    }
}

fn main() -> io::Result<()> {
    let args = Args::parse();

    let env_filter = EnvFilter::try_from_env("RUST_LOG")
        .unwrap_or_else(|_| EnvFilter::from_default_env().add_directive(Level::INFO.into()));
    tracing_subscriber::fmt()
        .with_writer(io::stdout)
        .with_env_filter(env_filter)
        .compact()
        .init();

    let out = fs::File::create_new(args.out)?;
    let mut rewriter = Rewriter::new(Box::new(out), FileFormat::Pcap, vec![]);
    // 262144 is the default `snaplen` in tcpdump. Hardcoded here for the sake of "quick and dirty".
    rewriter.writer.init_file(262144, Linktype::ETHERNET)?;

    let url = "mysql://127.0.0.1:4002/public";
    let pool = Pool::new(url).unwrap_or_else(|e| panic!("Failed to create mysql conn: '{e}'"));
    let mut conn = pool
        .get_conn()
        .unwrap_or_else(|e| panic!("Failed to get mysql conn: '{e}'"));

    let records: Vec<PacketRecord> = conn
        .query(args.sql)
        .unwrap_or_else(|e| panic!("Failed to do query: '{e}'"));

    for (i, record) in records.iter().enumerate() {
        if record.link_type != Linktype::ETHERNET {
            panic!("Currently the link type must be 'ethernet'!");
        }

        let packet = Packet {
            interface: 0,
            ts: record.ts,
            link_type: record.link_type,
            data: PacketData::L2(&record.packet_data),
            caplen: record.packet_data.len() as u32,
            origlen: record.length,
            pcap_index: i,
        };
        rewriter
            .writer
            .write_packet(&packet, &record.packet_data, 0)?;
    }
    Ok(())
}
