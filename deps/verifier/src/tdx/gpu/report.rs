use anyhow::{anyhow, Result};
use log::debug;
use std::collections::HashMap;

use super::opaque_data::OpaqueData;

#[derive(Debug)]
#[allow(dead_code)]
pub struct AttestationReport {
    pub spdm_version: u8,
    pub response_code: u8,
    pub param1: u8,
    pub param2: u8,
    pub number_of_blocks: u8,
    pub measurement_record_length: u32,
    pub measurements: HashMap<usize, String>,
    pub nonce: Vec<u8>,
    pub opaque_data: OpaqueData,
    pub signature: Vec<u8>,
}

impl AttestationReport {
    /// Parse compound attestation report
    /// Format: [SPDM request message (37 bytes)] + [SPDM response message]
    pub fn parse(data: &[u8]) -> Result<Self> {
        // Compound attestation report contains 37-byte request message + response message
        const REQUEST_MESSAGE_LENGTH: usize = 37;

        if data.len() < REQUEST_MESSAGE_LENGTH + 42 {
            return Err(anyhow!(
                "Insufficient data length to parse attestation report"
            ));
        }

        debug!("Raw data length: {} bytes", data.len());
        debug!(
            "Skipping {} bytes of request message",
            REQUEST_MESSAGE_LENGTH
        );

        // Skip request message and start parsing from response message
        let response_data = &data[REQUEST_MESSAGE_LENGTH..];
        debug!(
            "Response message data length: {} bytes",
            response_data.len()
        );

        Self::parse_response_message(response_data)
    }

    /// Parse SPDM response message
    fn parse_response_message(data: &[u8]) -> Result<Self> {
        if data.len() < 42 {
            return Err(anyhow!(
                "Insufficient response message data length to parse SPDM response message"
            ));
        }

        let mut offset = 0;

        // Parse SPDM response message header
        let spdm_version = data[offset];
        offset += 1;

        let response_code = data[offset];
        offset += 1;

        let param1 = data[offset];
        offset += 1;

        let param2 = data[offset];
        offset += 1;

        let number_of_blocks = data[offset];
        offset += 1;

        // Parse measurement record length (3 bytes, little endian)
        if offset + 3 > data.len() {
            return Err(anyhow!(
                "Insufficient data to read measurement record length"
            ));
        }
        let measurement_record_length =
            u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], 0]);
        offset += 3;

        debug!("SPDM version: 0x{:02X}", spdm_version);
        debug!("Response code: 0x{:02X}", response_code);
        debug!("Number of measurement blocks: {}", number_of_blocks);
        debug!("Measurement record length: {}", measurement_record_length);

        // Parse measurement record
        if offset + measurement_record_length as usize > data.len() {
            return Err(anyhow!(
                "Insufficient data to read measurement record, need {} bytes, remaining {} bytes",
                measurement_record_length,
                data.len() - offset
            ));
        }
        let measurements = Self::parse_measurement_record(
            &data[offset..offset + measurement_record_length as usize],
            number_of_blocks,
        )?;
        offset += measurement_record_length as usize;

        // Parse nonce (32 bytes)
        if offset + 32 > data.len() {
            return Err(anyhow!(
                "Insufficient data to read nonce, need 32 bytes, remaining {} bytes",
                data.len() - offset
            ));
        }
        let nonce = data[offset..offset + 32].to_vec();
        offset += 32;

        // Parse opaque data length (2 bytes, little endian)
        if offset + 2 > data.len() {
            return Err(anyhow!(
                "Insufficient data to read opaque data length, need 2 bytes, remaining {} bytes",
                data.len() - offset
            ));
        }
        let opaque_length = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;

        debug!(
            "Opaque data length: {} bytes, current offset: {}",
            opaque_length, offset
        );
        debug!("Data content from offset: {:02X?}", &data[offset..]);
        debug!("Data length from offset: {} bytes", data[offset..].len());

        // Parse opaque data
        if offset + opaque_length > data.len() {
            return Err(anyhow!(
                "Insufficient data to read opaque data, need {} bytes, remaining {} bytes",
                opaque_length,
                data.len() - offset
            ));
        }
        let opaque_data = OpaqueData::parse(&data[offset..offset + opaque_length])?;
        offset += opaque_length;

        // Parse signature (all remaining data)
        let signature = data[offset..].to_vec();
        debug!("Signature length: {} bytes", signature.len());
        debug!("Signature content: {:02X?}", signature);

        Ok(AttestationReport {
            spdm_version,
            response_code,
            param1,
            param2,
            number_of_blocks,
            measurement_record_length,
            measurements,
            nonce,
            opaque_data,
            signature,
        })
    }

    fn parse_measurement_record(
        data: &[u8],
        number_of_blocks: u8,
    ) -> Result<HashMap<usize, String>> {
        let mut measurements = HashMap::new();
        let mut offset = 0;

        debug!(
            "Parsing measurement record, data length: {} bytes, block count: {}",
            data.len(),
            number_of_blocks
        );

        for block_idx in 0..number_of_blocks {
            if offset >= data.len() {
                debug!(
                    "Warning: insufficient data for measurement block {}",
                    block_idx
                );
                break;
            }

            // Parse measurement block header
            let index = data[offset] as usize;
            offset += 1;

            let measurement_spec = data[offset];
            offset += 1;

            if offset + 2 > data.len() {
                return Err(anyhow!("Insufficient data to read measurement size"));
            }
            let measurement_size = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
            offset += 2;

            debug!(
                "Measurement block {}: spec=0x{:02X}, size={}",
                index, measurement_spec, measurement_size
            );
            debug!(
                "Current offset: {}, data length: {}, need to read: {}",
                offset,
                data.len(),
                measurement_size
            );

            // Verify measurement spec is DMTF (bit 0 = 1)
            if measurement_spec & 0x01 == 0 {
                return Err(anyhow!(
                    "Unsupported measurement spec: 0x{:02X}",
                    measurement_spec
                ));
            }

            // Parse DMTF measurement
            if offset + measurement_size > data.len() {
                debug!(
                    "Insufficient data: offset={}, measurement_size={}, data.len()={}",
                    offset,
                    measurement_size,
                    data.len()
                );
                return Err(anyhow!(
                    "Insufficient data to read measurement data, need {} bytes, remaining {} bytes",
                    measurement_size,
                    data.len() - offset
                ));
            }
            let measurement_value =
                Self::parse_dmtf_measurement(&data[offset..offset + measurement_size])?;
            offset += measurement_size;

            measurements.insert(index, measurement_value);
        }

        debug!(
            "Measurement record parsing completed, used {} bytes",
            offset
        );
        Ok(measurements)
    }

    fn parse_dmtf_measurement(data: &[u8]) -> Result<String> {
        if data.len() < 3 {
            return Err(anyhow!("Insufficient DMTF measurement data length"));
        }

        let value_type = data[0];
        let value_size = u16::from_le_bytes([data[1], data[2]]) as usize;

        debug!(
            "DMTF measurement: type=0x{:02X}, size={}",
            value_type, value_size
        );

        if 3 + value_size > data.len() {
            return Err(anyhow!("Insufficient DMTF measurement value data length"));
        }

        let measurement_value = &data[3..3 + value_size];
        Ok(hex::encode(measurement_value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_data() -> Vec<u8> {
        let mut data = vec![0u8; 37]; // Request message
        let mut response_data = Vec::new();
        
        // SPDM header
        response_data.extend_from_slice(&[0x10, 0x20, 0x30, 0x40, 0x02]); // version, response_code, param1, param2, blocks
        response_data.extend_from_slice(&[0x40, 0x00, 0x00]); // measurement_record_length (64 bytes)
        
        // Measurement record
        // Block 1
        response_data.extend_from_slice(&[0x01, 0x01]); // index, measurement_spec
        response_data.extend_from_slice(&[0x10, 0x00]); // measurement_size (16 bytes)
        response_data.extend_from_slice(&[0x01]); // value_type
        response_data.extend_from_slice(&[0x0D, 0x00]); // value_size (13 bytes)
        response_data.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D]); // value
        
        // Block 2
        response_data.extend_from_slice(&[0x02, 0x01]); // index, measurement_spec
        response_data.extend_from_slice(&[0x10, 0x00]); // measurement_size (16 bytes)
        response_data.extend_from_slice(&[0x01]); // value_type
        response_data.extend_from_slice(&[0x0D, 0x00]); // value_size (13 bytes)
        response_data.extend_from_slice(&[0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D]); // value

        // Nonce
        response_data.extend_from_slice(&[0xFF; 32]);
        
        // Opaque data
        let mut opaque_data = Vec::new();
        // Field 1: DRIVER_VERSION (type = 3)
        opaque_data.extend_from_slice(&[0x03, 0x00]); // type = 3 (DRIVER_VERSION)
        opaque_data.extend_from_slice(&[0x05, 0x00]); // size = 5
        opaque_data.extend_from_slice(b"1.2.3"); // value
        
        // Field 2: VBIOS_VERSION (type = 6)
        opaque_data.extend_from_slice(&[0x06, 0x00]); // type = 6 (VBIOS_VERSION)
        opaque_data.extend_from_slice(&[0x05, 0x00]); // size = 5
        opaque_data.extend_from_slice(b"4.5.6"); // value
        
        // Add opaque data length and content
        let opaque_len = opaque_data.len();
        debug!("Opaque data length before adding to main data: {} bytes", opaque_len);
        debug!("Opaque data content: {:02X?}", opaque_data);
        
        // Add opaque data length in little endian format
        response_data.extend_from_slice(&[opaque_len as u8, 0x00]); // opaque_length (little endian)
        response_data.extend_from_slice(&opaque_data);
        
        // Signature (use 0x00 instead of 0x55 to avoid confusion with length bytes)
        response_data.extend_from_slice(&[0x00; 46]); // signature data
        
        debug!("Response data length: {} bytes", response_data.len());
        debug!("Response data content: {:02X?}", response_data);
        
        // Combine request and response data
        data.extend_from_slice(&response_data);
        
        debug!("Total data length: {} bytes", data.len());
        debug!("Total data content: {:02X?}", data);
        
        data
    }

    #[test]
    fn test_parse_valid_attestation_report() {
        let data = create_test_data();
        let result = AttestationReport::parse(&data);
        assert!(result.is_ok(), "Failed to parse attestation report: {:?}", result.err());
        
        let report = result.unwrap();
        assert_eq!(report.spdm_version, 0x10);
        assert_eq!(report.response_code, 0x20);
        assert_eq!(report.param1, 0x30);
        assert_eq!(report.param2, 0x40);
        assert_eq!(report.number_of_blocks, 0x02);
        assert_eq!(report.measurement_record_length, 0x40);
        assert_eq!(report.measurements.len(), 2);
        assert_eq!(report.nonce.len(), 32);
        assert_eq!(report.signature.len(), 40);
    }

    #[test]
    fn test_parse_insufficient_data_length() {
        let data = vec![0u8; 36]; // Less than required request message length
        let result = AttestationReport::parse(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_response_message_insufficient_length() {
        let data = vec![0u8; 41]; // Less than minimum response message length
        let result = AttestationReport::parse_response_message(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_measurement_record_invalid_spec() {
        let mut data = vec![0u8; 4];
        data[1] = 0x02; // Invalid measurement spec (bit 0 = 0)
        let result = AttestationReport::parse_measurement_record(&data, 1);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_dmtf_measurement_insufficient_data() {
        let data = vec![0u8; 2]; // Less than required DMTF measurement length
        let result = AttestationReport::parse_dmtf_measurement(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_measurement_record_insufficient_data() {
        let mut data = vec![0u8; 10];
        data[0] = 0x01; // index
        data[1] = 0x01; // measurement_spec
        data[2] = 0xFF; // measurement_size (too large)
        data[3] = 0xFF;
        let result = AttestationReport::parse_measurement_record(&data, 1);
        assert!(result.is_err());
    }

    #[test]
    fn test_measurement_values() {
        let data = create_test_data();
        let result = AttestationReport::parse(&data);
        assert!(result.is_ok(), "Failed to parse attestation report: {:?}", result.err());
        
        let report = result.unwrap();
        assert!(report.measurements.contains_key(&1));
        assert!(report.measurements.contains_key(&2));
        
        let measurement1 = &report.measurements[&1];
        let measurement2 = &report.measurements[&2];
        
        assert_eq!(measurement1.len(), 26); // 13 bytes in hex = 26 chars
        assert_eq!(measurement2.len(), 26);
    }
}
