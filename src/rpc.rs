use std::{
    collections::HashMap,
    io::{self, Read},
    net::IpAddr,
};

use crate::{
    kms::{self, Service},
    wire::{Reader, align, invalid, put_u16, put_u32, put_u64},
};

const KMS_INTERFACE: [u8; 16] = [
    0x75, 0x21, 0xc8, 0x51, 0x4e, 0x84, 0x50, 0x47, 0xb0, 0xd8, 0xec, 0x25, 0x55, 0x55, 0xbc, 0x06,
];
const NDR32: [u8; 16] = [
    0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
];
const NDR64: [u8; 16] = [
    0x33, 0x05, 0x71, 0x71, 0xba, 0xbe, 0x37, 0x49, 0x83, 0x19, 0xb5, 0xdb, 0xef, 0x9c, 0xcc, 0x36,
];
const BTFN_PREFIX: [u8; 8] = [0x2c, 0x1c, 0xb7, 0x6c, 0x12, 0x98, 0x40, 0x45];
const FRAGMENT_SIZE: u16 = 5840;

pub struct Header {
    kind: u8,
    flags: u8,
    pub body_length: usize,
    call_id: u32,
}

impl Header {
    pub fn read(input: &mut impl Read) -> io::Result<Option<Self>> {
        let mut data = [0; 16];
        match input.read_exact(&mut data[..1]) {
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
            result => result?,
        }
        input.read_exact(&mut data[1..])?;
        let mut reader = Reader::new(&data);
        if reader.u8()? != 5 || reader.u8()? != 0 {
            return Err(invalid("unsupported RPC version"));
        }
        let kind = reader.u8()?;
        let flags = reader.u8()?;
        // 0x04 advertises header signing in Bind/AlterContext requests.
        let allowed_flags = if matches!(kind, 11 | 14) { 0x17 } else { 0x13 };
        if flags & 3 != 3 || flags & !allowed_flags != 0 {
            return Err(invalid("unsupported RPC fragmentation or flags"));
        }
        if reader.u32()? != 0x10 {
            return Err(invalid("unsupported RPC data representation"));
        }
        let length = reader.u16()?;
        if length < 16 || reader.u16()? != 0 {
            return Err(invalid("invalid RPC size or unsupported authentication"));
        }
        let call_id = reader.u32()?;
        Ok(Some(Self {
            kind,
            flags,
            body_length: usize::from(length) - 16,
            call_id,
        }))
    }

    fn response(&self, kind: u8, flags: u8, body: Vec<u8>) -> io::Result<Vec<u8>> {
        let length =
            u16::try_from(body.len() + 16).map_err(|_| invalid("RPC response too large"))?;
        let mut response = vec![5, 0, kind, flags, 0x10, 0, 0, 0];
        put_u16(&mut response, length);
        put_u16(&mut response, 0);
        put_u32(&mut response, self.call_id);
        response.extend_from_slice(&body);
        Ok(response)
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Syntax {
    Ndr32,
    Ndr64,
}

impl Syntax {
    fn read_size(self, reader: &mut Reader<'_>) -> io::Result<usize> {
        let size = match self {
            Self::Ndr32 => u64::from(reader.u32()?),
            Self::Ndr64 => reader.u64()?,
        };
        usize::try_from(size).map_err(|_| invalid("NDR length is too large"))
    }

    fn write_size(self, bytes: &mut Vec<u8>, size: usize) {
        match self {
            Self::Ndr32 => put_u32(bytes, size as u32),
            Self::Ndr64 => put_u64(bytes, size as u64),
        }
    }
}

struct Proposal {
    id: u16,
    interface: [u8; 16],
    version: u32,
    syntaxes: Vec<([u8; 16], u32)>,
}

impl Proposal {
    fn supports(&self, syntax: [u8; 16], version: u32) -> bool {
        self.interface == KMS_INTERFACE
            && self.version == 1
            && self.syntaxes.contains(&(syntax, version))
    }
}

pub struct Session {
    port: u16,
    peer_ip: IpAddr,
    association: u32,
    contexts: HashMap<u16, Syntax>,
    receive_limit: usize,
    send_limit: usize,
}

impl Session {
    pub fn new(port: u16, association: u32, peer_ip: IpAddr) -> Self {
        Self {
            port,
            peer_ip,
            association,
            contexts: HashMap::new(),
            receive_limit: usize::from(u16::MAX),
            send_limit: usize::from(u16::MAX),
        }
    }

    pub fn handle(&mut self, header: &Header, body: &[u8], kms: &Service) -> io::Result<Vec<u8>> {
        if body.len() + 16 > self.receive_limit {
            return Err(invalid("RPC request exceeds negotiated fragment size"));
        }
        let response = match header.kind {
            11 | 14 => self.bind(header, body),
            0 => self.request(header, body, kms),
            _ => Err(invalid("unsupported RPC packet type")),
        }?;
        if response.len() > self.send_limit {
            return Err(invalid("RPC response exceeds negotiated fragment size"));
        }
        Ok(response)
    }

    fn bind(&mut self, header: &Header, body: &[u8]) -> io::Result<Vec<u8>> {
        let mut reader = Reader::new(body);
        let max_transmit = reader.u16()?;
        let max_receive = reader.u16()?;
        reader.u32()?;
        let count = reader.u8()?;
        reader.take(3)?;
        if count == 0 {
            return Err(invalid("empty RPC context list"));
        }
        if header.kind == 11 && (max_transmit < 16 || max_receive < 16) {
            return Err(invalid("invalid RPC bind limits"));
        }
        let mut proposals = Vec::with_capacity(usize::from(count));
        for _ in 0..count {
            let id = reader.u16()?;
            let syntax_count = reader.u8()?;
            reader.u8()?;
            let interface = reader.array()?;
            let version = reader.u32()?;
            if syntax_count == 0 || proposals.iter().any(|p: &Proposal| p.id == id) {
                return Err(invalid("invalid RPC context list"));
            }
            let mut syntaxes = Vec::with_capacity(usize::from(syntax_count));
            for _ in 0..syntax_count {
                syntaxes.push((reader.array()?, reader.u32()?));
            }
            proposals.push(Proposal {
                id,
                interface,
                version,
                syntaxes,
            });
        }

        if header.kind == 11 {
            self.receive_limit = usize::from(max_transmit.min(FRAGMENT_SIZE));
            self.send_limit = usize::from(max_receive.min(FRAGMENT_SIZE));
            self.contexts.clear();
        }
        // AlterContext changes presentation contexts, not the Bind fragment limits.
        let prefer_ndr64 = proposals.iter().any(|p| p.supports(NDR64, 1));
        let mut response = Vec::new();
        put_u16(&mut response, self.send_limit as u16);
        put_u16(&mut response, self.receive_limit as u16);
        put_u32(&mut response, self.association);
        let address = if header.kind == 11 {
            format!("{}\0", self.port).into_bytes()
        } else {
            Vec::new()
        };
        put_u16(&mut response, address.len() as u16);
        response.extend_from_slice(&address);
        align(&mut response, 4);
        put_u32(&mut response, u32::from(count));

        for proposal in proposals {
            let accepted = if proposal.supports(NDR64, 1) {
                Some((Syntax::Ndr64, NDR64, 1))
            } else if !prefer_ndr64 && proposal.supports(NDR32, 2) {
                Some((Syntax::Ndr32, NDR32, 2))
            } else {
                None
            };
            let feature = proposal
                .syntaxes
                .iter()
                .find(|(id, _)| id[..8] == BTFN_PREFIX);
            let (result, reason, syntax, version) =
                if let Some((encoding, syntax, version)) = accepted {
                    self.contexts.insert(proposal.id, encoding);
                    (0, 0, syntax, version)
                } else if proposal.interface != KMS_INTERFACE || proposal.version != 1 {
                    (2, 1, [0; 16], 0)
                } else if let Some((feature, _)) = feature {
                    (
                        3,
                        u16::from_le_bytes([feature[8], feature[9]]) & 3,
                        [0; 16],
                        0,
                    )
                } else {
                    (2, 2, [0; 16], 0)
                };
            put_u16(&mut response, result);
            put_u16(&mut response, reason);
            response.extend_from_slice(&syntax);
            put_u32(&mut response, version);
        }
        let kind = if header.kind == 11 { 12 } else { 15 };
        // Clear the header-signing capability in both negotiation responses.
        let flags = if header.kind == 11 {
            3 | (header.flags & 0x10)
        } else {
            3
        };
        header.response(kind, flags, response)
    }

    fn request(&self, header: &Header, body: &[u8], kms: &Service) -> io::Result<Vec<u8>> {
        let mut reader = Reader::new(body);
        reader.u32()?;
        let context = reader.u16()?;
        let operation = reader.u16()?;
        let Some(&syntax) = self.contexts.get(&context) else {
            return fault(header, context, 0x1c01_0003);
        };
        if operation != 0 {
            return fault(header, context, 0x1c01_0002);
        }
        let result = request_data(syntax, &mut reader)
            .map_err(|_| kms::INVALID_DATA)
            .and_then(|data| kms.respond(data, self.peer_ip));
        let mut stub = Vec::new();
        let response_size = match &result {
            Ok(data) => data.len() as u32,
            Err(_) => 0,
        };
        // The IDL's int responseSize stays 32-bit in both transfer syntaxes.
        put_u32(&mut stub, response_size);
        if syntax == Syntax::Ndr64 {
            align(&mut stub, 8);
        }
        match result {
            Ok(data) => {
                syntax.write_size(&mut stub, 0x0002_0000);
                syntax.write_size(&mut stub, data.len());
                stub.extend_from_slice(&data);
                put_u32(&mut stub, 0);
            }
            Err(status) => {
                syntax.write_size(&mut stub, 0);
                put_u32(&mut stub, status);
            }
        }
        align(&mut stub, 4);
        let mut response = Vec::new();
        put_u32(&mut response, stub.len() as u32);
        put_u16(&mut response, context);
        put_u16(&mut response, 0);
        response.extend_from_slice(&stub);
        header.response(2, 3, response)
    }
}

fn request_data<'a>(syntax: Syntax, reader: &mut Reader<'a>) -> io::Result<&'a [u8]> {
    let size = reader.u32()? as usize;
    if syntax == Syntax::Ndr64 {
        // requestSize is a 32-bit int; only the following array count is 64-bit.
        reader.take(4)?;
    }
    if size != syntax.read_size(reader)? {
        return Err(invalid("inconsistent NDR request lengths"));
    }
    reader.take(size)
}

fn fault(header: &Header, context: u16, status: u32) -> io::Result<Vec<u8>> {
    let mut response = Vec::new();
    put_u32(&mut response, 16);
    put_u16(&mut response, context);
    put_u16(&mut response, 0);
    put_u32(&mut response, status);
    put_u32(&mut response, 0);
    header.response(3, 0x23, response)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn header_sign_bit_does_not_enable_request_cancellation_or_authentication() {
        for (kind, auth_length) in [(0, 0_u16), (11, 1), (14, 1)] {
            let mut header = vec![5, 0, kind, 0x07, 0x10, 0, 0, 0];
            put_u16(&mut header, 16);
            put_u16(&mut header, auth_length);
            put_u32(&mut header, 1);
            assert!(Header::read(&mut Cursor::new(header)).is_err());
        }
    }
}
