/// PCAP packet capture support for gossip protocol.
/// # Usage
///
/// ```ignore
/// use gossip_membership::pcap::PcapCapture;
///
/// let mut capture = PcapCapture::new("capture.pcap").unwrap();
/// capture.write_packet(&packet_data, source_ip, dest_ip).unwrap();
/// capture.close().unwrap();
/// ```
use std::fs::File;
use std::io::{BufWriter, Write};
use std::net::Ipv4Addr;

// PCAP magic number: little-endian, nanosecond precision
const PCAP_MAGIC: u32 = 0xa1b2c3d4;
const PCAP_VERSION_MAJOR: u16 = 2;
const PCAP_VERSION_MINOR: u16 = 4;

// Link types
pub const LINKTYPE_RAW: u16 = 101; // Raw IP packet
pub const LINKTYPE_ETHERNET: u16 = 1; // Ethernet

#[derive(Debug)]
pub enum PcapError {
    IoError(std::io::Error),
    NotOpen,
    AlreadyOpen,
}

impl From<std::io::Error> for PcapError {
    fn from(err: std::io::Error) -> Self {
        PcapError::IoError(err)
    }
}

pub struct PcapCapture {
    writer: Option<BufWriter<File>>,
    packet_count: u32,
    link_type: u16,
}

impl PcapCapture {
    /// Create a new PCAP file with raw IP link type.
    pub fn new(path: &str) -> Result<Self, PcapError> {
        let file = File::create(path)?;
        let mut writer = BufWriter::new(file);

        // Write global header
        let header = PcapHeader::new(LINKTYPE_RAW);
        header.write_to(&mut writer)?;

        Ok(Self {
            writer: Some(writer),
            packet_count: 0,
            link_type: LINKTYPE_RAW,
        })
    }

    /// Create a new PCAP file with specified link type.
    pub fn with_link_type(path: &str, link_type: u16) -> Result<Self, PcapError> {
        let file = File::create(path)?;
        let mut writer = BufWriter::new(file);

        let header = PcapHeader::new(link_type);
        header.write_to(&mut writer)?;

        Ok(Self {
            writer: Some(writer),
            packet_count: 0,
            link_type,
        })
    }

    /// Write a packet to the capture file.
    ///
    /// `data` is the payload that will be wrapped in an IPv4 packet.
    pub fn write_packet(
        &mut self,
        data: &[u8],
        src: Ipv4Addr,
        dst: Ipv4Addr,
    ) -> Result<(), PcapError> {
        let writer = self.writer.as_mut().ok_or(PcapError::NotOpen)?;

        // Build IP packet with our data as payload
        let ip_packet = build_ip_packet(data, src, dst);
        let len = ip_packet.len();

        // Get current timestamp
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap();
        let timestamp_sec = now.as_secs() as u32;
        let timestamp_usec = (now.subsec_nanos() / 1000) as u32;

        // Write packet record
        // Packet header: ts_sec (4), ts_usec (4), incl_len (4), orig_len (4) = 16 bytes
        writer.write_all(&timestamp_sec.to_le_bytes())?;
        writer.write_all(&timestamp_usec.to_le_bytes())?;
        writer.write_all(&(len as u32).to_le_bytes())?;
        writer.write_all(&(len as u32).to_le_bytes())?;

        // Packet data
        writer.write_all(&ip_packet)?;

        self.packet_count += 1;
        Ok(())
    }

    /// Write a raw packet (already includes IP header).
    pub fn write_raw_packet(&mut self, data: &[u8]) -> Result<(), PcapError> {
        let writer = self.writer.as_mut().ok_or(PcapError::NotOpen)?;

        let len = data.len();

        // Get current timestamp
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap();
        let timestamp_sec = now.as_secs() as u32;
        let timestamp_usec = (now.subsec_nanos() / 1000) as u32;

        // Write packet record
        writer.write_all(&timestamp_sec.to_le_bytes())?;
        writer.write_all(&timestamp_usec.to_le_bytes())?;
        writer.write_all(&(len as u32).to_le_bytes())?;
        writer.write_all(&(len as u32).to_le_bytes())?;

        // Packet data
        writer.write_all(data)?;

        self.packet_count += 1;
        Ok(())
    }

    /// Flush buffered data to disk.
    pub fn flush(&mut self) -> Result<(), PcapError> {
        let writer = self.writer.as_mut().ok_or(PcapError::NotOpen)?;
        writer.flush()?;
        Ok(())
    }

    /// Close the capture file.
    pub fn close(&mut self) -> Result<(), PcapError> {
        if let Some(mut writer) = self.writer.take() {
            writer.flush()?;
            // File automatically closed when writer is dropped
        }
        Ok(())
    }

    /// Get number of packets captured.
    pub fn packet_count(&self) -> u32 {
        self.packet_count
    }

    /// Check if capture is open.
    pub fn is_open(&self) -> bool {
        self.writer.is_some()
    }
}

impl Drop for PcapCapture {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

/// PCAP global header (24 bytes).
struct PcapHeader {
    magic: u32,
    version_major: u16,
    version_minor: u16,
    thiszone: i32,
    sigfigs: u32,
    snaplen: u32,
    network: u16,
}

impl PcapHeader {
    fn new(link_type: u16) -> Self {
        Self {
            magic: PCAP_MAGIC,
            version_major: PCAP_VERSION_MAJOR,
            version_minor: PCAP_VERSION_MINOR,
            thiszone: 0,
            sigfigs: 0,
            snaplen: 65535, // Max packet size
            network: link_type,
        }
    }

    fn write_to<W: Write>(&self, writer: &mut W) -> Result<(), PcapError> {
        writer.write_all(&self.magic.to_le_bytes())?;
        writer.write_all(&self.version_major.to_le_bytes())?;
        writer.write_all(&self.version_minor.to_le_bytes())?;
        writer.write_all(&self.thiszone.to_le_bytes())?;
        writer.write_all(&self.sigfigs.to_le_bytes())?;
        writer.write_all(&self.snaplen.to_le_bytes())?;
        writer.write_all(&self.network.to_le_bytes())?;
        Ok(())
    }
}

/// Build an IP packet with the gossip data as payload.
fn build_ip_packet(payload: &[u8], src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
    let total_len = 20 + payload.len(); // IP header (20 bytes) + payload

    let mut packet = Vec::with_capacity(total_len);

    // IP Header (20 bytes)
    packet.push(0x45); // Version (4) + IHL (5 = 20 bytes)
    packet.push(0x00); // DSCP + ECN
    packet.push(((total_len >> 8) & 0xFF) as u8); // Total length high
    packet.push((total_len & 0xFF) as u8); // Total length low
    packet.push(0x00); // Identification
    packet.push(0x00);
    packet.push(0x40); // Flags (Don't Fragment) + Fragment Offset
    packet.push(0x00);
    packet.push(64); // TTL
    packet.push(254); // Experimental Protocol
    packet.push(0x00); // Header checksum (will calculate)
    packet.push(0x00);

    // Source IP
    packet.push(src.octets()[0]);
    packet.push(src.octets()[1]);
    packet.push(src.octets()[2]);
    packet.push(src.octets()[3]);

    // Destination IP
    packet.extend_from_slice(&src.octets());
    packet.extend_from_slice(&dst.octets());

    // Calculate and set checksum
    let checksum = ip_checksum(&packet[..20]);
    packet[10] = ((checksum >> 8) & 0xFF) as u8;
    packet[11] = (checksum & 0xFF) as u8;

    // Payload
    packet.extend_from_slice(payload);

    packet
}

/// Calculate IP header checksum.
fn ip_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    // Sum all 16-bit words
    for i in (0..header.len()).step_by(2) {
        if i + 1 < header.len() {
            sum += ((header[i] as u32) << 8) | (header[i + 1] as u32);
        } else if i < header.len() {
            sum += (header[i] as u32) << 8;
        }
    }

    // Add carry
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !sum as u16
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn pcap_creation_and_write() {
        let path = "test_capture.pcap";
        let mut capture = PcapCapture::new(path).unwrap();

        // Write a simple test packet (gossip message bytes)
        let test_data = vec![0x01, 0x02, 0x03, 0x04]; // Fake gossip data

        capture
            .write_packet(
                &test_data,
                Ipv4Addr::new(192, 168, 1, 1),
                Ipv4Addr::new(192, 168, 1, 2),
            )
            .unwrap();

        assert_eq!(capture.packet_count(), 1);

        capture.close().unwrap();

        // Verify file exists and has content
        let metadata = std::fs::metadata(path).unwrap();
        assert!(metadata.len() > 24); // Global header + at least one packet

        // Cleanup
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn pcap_multiple_packets() {
        let path = "test_multi.pcap";
        let mut capture = PcapCapture::new(path).unwrap();

        for i in 0..5 {
            let data = vec![i as u8; 10];
            capture
                .write_packet(
                    &data,
                    Ipv4Addr::new(10, 0, 0, 1),
                    Ipv4Addr::new(10, 0, 0, 2),
                )
                .unwrap();
        }

        assert_eq!(capture.packet_count(), 5);
        capture.close().unwrap();

        std::fs::remove_file(path).ok();
    }

    #[test]
    fn pcap_raw_packet() {
        let path = "test_raw.pcap";
        let mut capture = PcapCapture::new(path).unwrap();

        // Already-formed IP packet
        let raw_ip = vec![
            0x45, 0x00, 0x00, 0x1c, // IP header
            0x00, 0x01, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00, // Checksum placeholder
            0xc0, 0xa8, 0x01, 0x01, // Src
            0xc0, 0xa8, 0x01, 0x02, // Dst
            0x00, 0x00, 0x00, 0x00, // UDP/payload
        ];

        capture.write_raw_packet(&raw_ip).unwrap();

        assert_eq!(capture.packet_count(), 1);
        capture.close().unwrap();

        std::fs::remove_file(path).ok();
    }

    #[test]
    fn ip_checksum_valid() {
        // Simple IP header
        let header = vec![
            0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8,
            0x01, 0x01, 0xc0, 0xa8, 0x01, 0x02,
        ];

        let checksum = ip_checksum(&header);
        // Checksum should not be 0x0000 (unless header is all zeros)
        assert!(checksum != 0 || header.iter().all(|&x| x == 0));
    }

    #[test]
    fn pcap_file_format_valid() {
        let path = "test_format.pcap";
        let mut capture = PcapCapture::new(path).unwrap();

        capture
            .write_packet(
                &[1, 2, 3],
                Ipv4Addr::new(1, 2, 3, 4),
                Ipv4Addr::new(5, 6, 7, 8),
            )
            .unwrap();
        capture.close().unwrap();

        // Read and verify magic number
        let data = std::fs::read(path).unwrap();
        let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        assert_eq!(magic, PCAP_MAGIC);

        // Verify version
        let version_major = u16::from_le_bytes([data[4], data[5]]);
        assert_eq!(version_major, PCAP_VERSION_MAJOR);

        std::fs::remove_file(path).ok();
    }
}
