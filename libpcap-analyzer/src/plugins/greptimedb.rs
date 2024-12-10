use crate::{
    plugin_builder, PacketInfo, Plugin, PluginResult, PLUGIN_L1, PLUGIN_L2, PLUGIN_L3, PLUGIN_L4,
};
use greptimedb_ingester::api::v1::{
    ColumnDataType, Row, RowInsertRequest, RowInsertRequests, Rows,
};
use greptimedb_ingester::helpers::schema::{field, timestamp};
use greptimedb_ingester::helpers::values::{
    binary_value, string_value, timestamp_microsecond_value, u16_value, u32_value, u8_value,
};
use greptimedb_ingester::{ClientBuilder, Database};
use libpcap_tools::pcap_parser::data::PacketData;
use libpcap_tools::{Packet, ThreeTuple};
use pnet_packet::ip::IpNextHeaderProtocol;
use std::fmt::{Debug, Formatter};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use tokio::sync::mpsc;

plugin_builder!(Greptimedb, GreptimedbBuilder, Greptimedb::new);

struct Greptimedb {
    interested_layers: u16,
    tx: mpsc::Sender<Option<RowInsertRequest>>,
    stopped: Arc<AtomicBool>,
}

impl Greptimedb {
    fn new(config: &libpcap_tools::Config) -> Self {
        let mut interested_layers = 0;
        config
            .get("greptimedb-interested-layers")
            .unwrap_or("L4")
            .split(',')
            .for_each(|l| match l {
                "L1" => interested_layers |= PLUGIN_L1,
                "L2" => interested_layers |= PLUGIN_L2,
                "L3" => interested_layers |= PLUGIN_L3,
                "L4" => interested_layers |= PLUGIN_L4,
                _ => panic!("Unknown interested layer: '{}'", l),
            });

        let (tx, mut rx) = mpsc::channel::<Option<RowInsertRequest>>(1024);
        let stopped = Arc::new(AtomicBool::new(false));

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap_or_else(|e| panic!("Failed to start tokio runtime: {}", e));
        std::thread::spawn({
            let stopped = stopped.clone();
            move || {
                rt.block_on(async move {
                    create_table().await;

                    let client = ClientBuilder::default()
                        .peers(vec!["127.0.0.1:4001"])
                        .build();
                    let client = Database::new_with_dbname("public", client);

                    info!("Ready to ingest some tcpdump records to Greptimedb!");
                    while let Some(insert) = rx.recv().await {
                        let Some(insert) = insert else {
                            info!("Received stop signal, quit ingesting!");
                            break;
                        };

                        let result = client
                            .row_insert(RowInsertRequests {
                                inserts: vec![insert],
                            })
                            .await;
                        result.unwrap_or_else(|e| {
                            panic!("Failed to insert tcpdump record to GreptimeDB, error: {e}")
                        });
                    }

                    stopped.store(true, std::sync::atomic::Ordering::Relaxed);
                })
            }
        });
        Self {
            interested_layers,
            tx,
            stopped,
        }
    }

    fn send(&self, insert: RowInsertRequest) -> PluginResult {
        self.tx
            .blocking_send(Some(insert))
            .unwrap_or_else(|e| panic!("Client error: {}", e));
        PluginResult::None
    }
}

impl Plugin for Greptimedb {
    fn name(&self) -> &'static str {
        "Greptimedb"
    }

    fn plugin_type(&self) -> u16 {
        self.interested_layers
    }

    fn post_process(&mut self) {
        let _ = self.tx.blocking_send(None);

        while !self.stopped.load(std::sync::atomic::Ordering::Relaxed) {
            debug!(
                "Greptimedb plugin has unfinished {} tasks",
                self.tx.max_capacity() - self.tx.capacity(),
            );
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
    }

    fn handle_layer_physical<'s, 'i>(
        &'s mut self,
        packet: &'s Packet,
        _data: &'i [u8],
    ) -> PluginResult<'i> {
        let record = TcpdumpRecord::new(1, packet);
        trace!("Sending tcpdump record: {:?}", record);
        let insert = record.into();
        self.send(insert);
        PluginResult::None
    }

    fn handle_layer_link<'s, 'i>(
        &'s mut self,
        packet: &'s Packet,
        _linklayertype: u16,
        _data: &'i [u8],
    ) -> PluginResult<'i> {
        let record = TcpdumpRecord::new(2, packet);
        trace!("Sending tcpdump record: {:?}", record);
        let insert = record.into();
        self.send(insert);
        PluginResult::None
    }

    fn handle_layer_network<'s, 'i>(
        &'s mut self,
        packet: &'s Packet,
        _payload: &'i [u8],
        t3: &'s ThreeTuple,
    ) -> PluginResult<'i> {
        let mut record = TcpdumpRecord::new(3, packet);
        record.src = t3.src.to_string();
        record.dst = t3.dst.to_string();
        record.protocol = IpNextHeaderProtocol::new(t3.l4_proto).to_string();
        trace!("Sending tcpdump record: {:?}", record);

        let insert = record.into();
        self.send(insert);
        PluginResult::None
    }

    fn handle_layer_transport<'s, 'i>(
        &'s mut self,
        packet: &'s Packet,
        pinfo: &PacketInfo,
    ) -> PluginResult<'i> {
        // Ignores dummy L4 packet, see function `handle_l4_tcp`.
        if pinfo.l4_data.is_empty() {
            return PluginResult::None;
        }

        let mut record = TcpdumpRecord::new(4, packet);
        record.src = pinfo.five_tuple.src.to_string();
        record.src_port = pinfo.five_tuple.src_port;
        record.dst = pinfo.five_tuple.dst.to_string();
        record.dst_port = pinfo.five_tuple.dst_port;
        record.protocol = IpNextHeaderProtocol::new(pinfo.five_tuple.proto).to_string();
        trace!("Sending tcpdump record: {:?}", record);

        let insert = record.into();
        self.send(insert);
        PluginResult::None
    }
}

struct TcpdumpRecord {
    level: u8,
    pcap_index: u32,
    ts: i64,
    src: String,
    src_port: u16,
    dst: String,
    dst_port: u16,
    link_type: u8,
    protocol: String,
    length: u32,
    packet_data: Vec<u8>,
}

impl Debug for TcpdumpRecord {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[L{}] {}: TcpdumpRecord {{ts = {}, src = '{}:{}', dest = '{}:{}', \
            link_type = {}, protocol = '{}', length = {}, packet_data: <bytes>}}",
            self.level,
            self.pcap_index,
            self.ts,
            self.src,
            self.src_port,
            self.dst,
            self.dst_port,
            self.link_type,
            self.protocol,
            self.length,
        )
    }
}

impl TcpdumpRecord {
    fn new(level: u8, packet: &Packet) -> Self {
        let packet_data = match packet.data {
            PacketData::L2(x) => x.to_vec(),
            PacketData::L3(_, x) => x.to_vec(),
            PacketData::L4(_, x) => x.to_vec(),
            PacketData::Unsupported(x) => x.to_vec(),
        };
        Self {
            level,
            pcap_index: packet.pcap_index as u32,
            ts: packet.ts.secs as i64 * 1_000_000 + packet.ts.micros as i64,
            src: "".to_string(),
            src_port: 0,
            dst: "".to_string(),
            dst_port: 0,
            link_type: packet.link_type.0 as u8,
            protocol: "".to_string(),
            length: packet_data.len() as u32,
            packet_data,
        }
    }
}

impl From<TcpdumpRecord> for RowInsertRequest {
    fn from(value: TcpdumpRecord) -> Self {
        let schema = vec![
            field("level", ColumnDataType::Uint8),
            field("pcap_index", ColumnDataType::Uint32),
            timestamp("ts", ColumnDataType::TimestampMicrosecond),
            field("src", ColumnDataType::String),
            field("src_port", ColumnDataType::Uint16),
            field("dst", ColumnDataType::String),
            field("dst_port", ColumnDataType::Uint16),
            field("link_type", ColumnDataType::Uint8),
            field("protocol", ColumnDataType::String),
            field("length", ColumnDataType::Uint32),
            field("packet_data", ColumnDataType::Binary),
        ];
        let row = Row {
            values: vec![
                u8_value(value.level),
                u32_value(value.pcap_index),
                timestamp_microsecond_value(value.ts),
                string_value(value.src),
                u16_value(value.src_port),
                string_value(value.dst),
                u16_value(value.dst_port),
                u8_value(value.link_type),
                string_value(value.protocol),
                u32_value(value.length),
                binary_value(value.packet_data),
            ],
        };
        RowInsertRequest {
            table_name: "tcpdumps".to_string(),
            rows: Some(Rows {
                schema,
                rows: vec![row],
            }),
        }
    }
}

async fn create_table() {
    let s = r#"
CREATE TABLE IF NOT EXISTS `tcpdumps` (
  `level` UINT8,
  `pcap_index` UINT32,
  `ts` TIMESTAMP(6) TIME INDEX,
  `src` STRING,
  `src_port` UINT16,
  `dst` STRING,
  `dst_port` UINT16,
  `link_type` UINT8,
  `protocol` STRING,
  `length` UINT32,
  `packet_data` BINARY,
) WITH (
  'append_mode' = 'true',
)"#;
    let result = reqwest::Client::new()
        .post("http://127.0.0.1:4000/v1/sql?db=public")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(format!("sql={}", s))
        .send()
        .await;
    debug!("Created table `tcpdumps` in GreptimeDB, result: '{result:?}'");
}
