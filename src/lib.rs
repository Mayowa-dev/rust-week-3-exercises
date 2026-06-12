use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use std::fmt;
use std::ops::Deref;

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct CompactSize {
    pub value: u64,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum BitcoinError {
    InsufficientBytes,
    InvalidFormat,
}

impl CompactSize {
    pub fn new(value: u64) -> Self {
        Self { value }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        match self.value {
            0x00..=0xFC => vec![self.value as u8],
            0xFD..=0xFFFF => {
                let mut data = Vec::with_capacity(3);
                data.push(0xFD);
                data.extend_from_slice(&(self.value as u16).to_le_bytes());
                data
            }
            0x10000..=0xFFFFFFFF => {
                let mut data = Vec::with_capacity(5);
                data.push(0xFE);
                data.extend_from_slice(&(self.value as u32).to_le_bytes());
                data
            }
            _ => {
                let mut data = Vec::with_capacity(9);
                data.push(0xFF);
                data.extend_from_slice(&self.value.to_le_bytes());
                data
            }
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<(Self, usize), BitcoinError> {
        let prefix = *bytes.get(0).ok_or(BitcoinError::InsufficientBytes)?;
        match prefix {
            0x00..=0xFC => Ok((Self::new(prefix as u64), 1)),
            0xFD => {
                if bytes.len() < 3 {
                    return Err(BitcoinError::InsufficientBytes);
                }
                let value = u16::from_le_bytes(bytes[1..3].try_into().unwrap()) as u64;
                if value <= 0xFC {
                    return Err(BitcoinError::InvalidFormat);
                }
                Ok((Self::new(value), 3))
            }
            0xFE => {
                if bytes.len() < 5 {
                    return Err(BitcoinError::InsufficientBytes);
                }
                let value = u32::from_le_bytes(bytes[1..5].try_into().unwrap()) as u64;
                if value <= 0xFFFF {
                    return Err(BitcoinError::InvalidFormat);
                }
                Ok((Self::new(value), 5))
            }
            0xFF => {
                if bytes.len() < 9 {
                    return Err(BitcoinError::InsufficientBytes);
                }
                let value = u64::from_le_bytes(bytes[1..9].try_into().unwrap());
                if value <= 0xFFFFFFFF {
                    return Err(BitcoinError::InvalidFormat);
                }
                Ok((Self::new(value), 9))
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Txid(pub [u8; 32]);

impl Serialize for Txid {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let hex_string = hex::encode(self.0);
        serializer.serialize_str(&hex_string)
    }
}

impl<'de> Deserialize<'de> for Txid {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let data = hex::decode(&s).map_err(D::Error::custom)?;
        if data.len() != 32 {
            return Err(D::Error::custom("invalid txid length"));
        }
        let mut txid = [0u8; 32];
        txid.copy_from_slice(&data);
        Ok(Txid(txid))
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct OutPoint {
    pub txid: Txid,
    pub vout: u32,
}

impl OutPoint {
    pub fn new(txid: [u8; 32], vout: u32) -> Self {
        Self {
            txid: Txid(txid),
            vout,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(36);
        result.extend_from_slice(&self.txid.0);
        result.extend_from_slice(&self.vout.to_le_bytes());
        result
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<(Self, usize), BitcoinError> {
        if bytes.len() < 36 {
            return Err(BitcoinError::InsufficientBytes);
        }
        let mut txid = [0u8; 32];
        txid.copy_from_slice(&bytes[0..32]);
        let vout = u32::from_le_bytes(bytes[32..36].try_into().unwrap());
        Ok((Self::new(txid, vout), 36))
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct Script {
    pub bytes: Vec<u8>,
}

impl Script {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = CompactSize::new(self.bytes.len() as u64).to_bytes();
        result.extend_from_slice(&self.bytes);
        result
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<(Self, usize), BitcoinError> {
        let (size, consumed) = CompactSize::from_bytes(bytes)?;
        let length = size.value as usize;
        if bytes.len() < consumed + length {
            return Err(BitcoinError::InsufficientBytes);
        }
        let data = bytes[consumed..consumed + length].to_vec();
        Ok((Self::new(data), consumed + length))
    }
}

impl Deref for Script {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct TransactionInput {
    pub previous_output: OutPoint,
    pub script_sig: Script,
    pub sequence: u32,
}

impl TransactionInput {
    pub fn new(previous_output: OutPoint, script_sig: Script, sequence: u32) -> Self {
        Self {
            previous_output,
            script_sig,
            sequence,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = self.previous_output.to_bytes();
        result.extend_from_slice(&self.script_sig.to_bytes());
        result.extend_from_slice(&self.sequence.to_le_bytes());
        result
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<(Self, usize), BitcoinError> {
        let (previous_output, consumed_outpoint) = OutPoint::from_bytes(bytes)?;
        let offset = consumed_outpoint;
        let (script_sig, consumed_script) = Script::from_bytes(&bytes[offset..])?;
        let offset = offset + consumed_script;
        if bytes.len() < offset + 4 {
            return Err(BitcoinError::InsufficientBytes);
        }
        let sequence = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
        Ok((Self::new(previous_output, script_sig, sequence), offset + 4))
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct BitcoinTransaction {
    pub version: u32,
    pub inputs: Vec<TransactionInput>,
    pub lock_time: u32,
}

impl BitcoinTransaction {
    pub fn new(version: u32, inputs: Vec<TransactionInput>, lock_time: u32) -> Self {
        Self {
            version,
            inputs,
            lock_time,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::new();
        result.extend_from_slice(&self.version.to_le_bytes());
        result.extend_from_slice(&CompactSize::new(self.inputs.len() as u64).to_bytes());
        for input in &self.inputs {
            result.extend_from_slice(&input.to_bytes());
        }
        result.extend_from_slice(&self.lock_time.to_le_bytes());
        result
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<(Self, usize), BitcoinError> {
        if bytes.len() < 4 {
            return Err(BitcoinError::InsufficientBytes);
        }
        let version = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        let mut offset = 4;
        let (count, count_size) = CompactSize::from_bytes(&bytes[offset..])?;
        offset += count_size;
        let mut inputs = Vec::with_capacity(count.value as usize);
        for _ in 0..count.value {
            let (input, consumed_input) = TransactionInput::from_bytes(&bytes[offset..])?;
            offset += consumed_input;
            inputs.push(input);
        }
        if bytes.len() < offset + 4 {
            return Err(BitcoinError::InsufficientBytes);
        }
        let lock_time = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
        Ok((Self::new(version, inputs, lock_time), offset + 4))
    }
}

impl fmt::Display for BitcoinTransaction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Version: {}", self.version)?;
        writeln!(f, "Inputs: {}", self.inputs.len())?;
        for (index, input) in self.inputs.iter().enumerate() {
            writeln!(f, "  Input {}:", index)?;
            writeln!(
                f,
                "    Previous Output TXID: {}",
                hex::encode(input.previous_output.txid.0)
            )?;
            writeln!(
                f,
                "    Previous Output Vout: {}",
                input.previous_output.vout
            )?;
            writeln!(f, "    ScriptSig Length: {}", input.script_sig.bytes.len())?;
            writeln!(f, "    ScriptSig: {}", hex::encode(&input.script_sig.bytes))?;
            writeln!(f, "    Sequence: {}", input.sequence)?;
        }
        write!(f, "Lock Time: {}", self.lock_time)
    }
}
