use core::fmt;
use std::ops::{Deref, DerefMut};

use enum_repr::EnumRepr;
use enumflags2::{bitflags, BitFlags};
use nom::{
    combinator::map_res,
    number::streaming::{be_u24, be_u8},
    sequence::tuple,
    IResult,
};
use tokio::io::{AsyncWrite, AsyncWriteExt};

/// This is sent by h2 clients after negotiating over ALPN, or when doing h2c.
pub const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

#[bitflags]
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DataFlags {
    Padded = 0x08,
    EndStream = 0x01,
}

#[bitflags]
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HeadersFlags {
    Priority = 0x20,
    Padded = 0x08,
    EndHeaders = 0x04,
    EndStream = 0x01,
}

#[bitflags]
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SettingsFlags {
    Ack = 0x01,
}

#[EnumRepr(type = "u8")]
#[derive(Debug)]
pub enum RawFrameType {
    Data = 0,
    Headers = 1,
    Priority = 2,
    RstStream = 3,
    Settings = 4,
    PushPromise = 5,
    Ping = 6,
    GoAway = 7,
    WindowUpdate = 8,
    Continuation = 9,
}

#[derive(Debug)]
pub enum FrameType {
    Data(BitFlags<DataFlags>),
    Headers(BitFlags<HeadersFlags>),
    Priority,
    RstStream,
    Settings(BitFlags<SettingsFlags>),
    PushPromise,
    Ping,
    GoAway,
    WindowUpdate,
    Continuation,
}

impl FrameType {
    fn encode(&self) -> (RawFrameType, u8) {
        match self {
            FrameType::Data(f) => (RawFrameType::Data, f.bits()),
            FrameType::Headers(f) => (RawFrameType::Headers, f.bits()),
            FrameType::Priority => (RawFrameType::Priority, 0),
            FrameType::RstStream => (RawFrameType::RstStream, 0),
            FrameType::Settings(f) => (RawFrameType::Settings, f.bits()),
            FrameType::PushPromise => (RawFrameType::PushPromise, 0),
            FrameType::Ping => (RawFrameType::Ping, 0),
            FrameType::GoAway => (RawFrameType::GoAway, 0),
            FrameType::WindowUpdate => (RawFrameType::WindowUpdate, 0),
            FrameType::Continuation => (RawFrameType::Continuation, 0),
        }
    }

    fn decode(ty: RawFrameType, flags: u8) -> Self {
        match ty {
            RawFrameType::Data => FrameType::Data(BitFlags::<DataFlags>::from_bits_truncate(flags)),
            RawFrameType::Headers => {
                FrameType::Headers(BitFlags::<HeadersFlags>::from_bits_truncate(flags))
            }
            RawFrameType::Priority => FrameType::Priority,
            RawFrameType::RstStream => FrameType::RstStream,
            RawFrameType::Settings => {
                FrameType::Settings(BitFlags::<SettingsFlags>::from_bits_truncate(flags))
            }
            RawFrameType::PushPromise => FrameType::PushPromise,
            RawFrameType::Ping => FrameType::Ping,
            RawFrameType::GoAway => FrameType::GoAway,
            RawFrameType::WindowUpdate => FrameType::WindowUpdate,
            RawFrameType::Continuation => FrameType::Continuation,
        }
    }
}

#[derive(Debug)]
pub struct Frame {
    pub frame_type: FrameType,
    pub reserved: u8,
    pub stream_id: u32,
    pub payload: OpaquePayload,
}

#[derive(Default)]
pub struct OpaquePayload(pub Vec<u8>);

impl Deref for OpaquePayload {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for OpaquePayload {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl fmt::Debug for OpaquePayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpaquePayload")
            .field("len", &self.0.len())
            .finish()
    }
}

impl Frame {
    pub fn new(frame_type: FrameType, stream_id: u32) -> Self {
        Self {
            frame_type,
            reserved: 0,
            stream_id,
            payload: Default::default(),
        }
    }

    pub fn parse(i: &[u8]) -> IResult<&[u8], Self> {
        let (i, (length, frame_type, flags, (reserved, stream_id))) = tuple((
            be_u24,
            map_res(be_u8, |u| {
                RawFrameType::from_repr(u).ok_or(nom::error::ErrorKind::OneOf)
            }),
            be_u8,
            parse_reserved_and_stream_id,
        ))(i)?;
        let (i, payload) = nom::bytes::streaming::take(length)(i)?;

        let frame_type = FrameType::decode(frame_type, flags);
        let frame = Frame {
            frame_type,
            reserved,
            stream_id,
            payload: OpaquePayload(payload.to_vec()),
        };
        Ok((i, frame))
    }

    pub async fn write(&self, w: &mut (dyn AsyncWrite + Unpin)) -> color_eyre::Result<()> {
        let mut header = [0u8; 9];
        {
            use byteorder::{BigEndian, WriteBytesExt};
            let mut header = &mut header[..];
            header.write_u24::<BigEndian>(self.payload.len() as _)?;
            let (ty, flags) = self.frame_type.encode();
            header.write_u8(ty.repr())?;
            header.write_u8(flags)?;
            header.write_u32::<BigEndian>(self.stream_id)?;
        }
        w.write_all(&header).await?;
        w.write_all(&self.payload).await?;

        Ok(())
    }
}

fn parse_reserved_and_stream_id(i: &[u8]) -> IResult<&[u8], (u8, u32)> {
    fn reserved(i: (&[u8], usize)) -> IResult<(&[u8], usize), u8> {
        nom::bits::streaming::take(1_usize)(i)
    }

    fn stream_id(i: (&[u8], usize)) -> IResult<(&[u8], usize), u32> {
        nom::bits::streaming::take(31_usize)(i)
    }

    nom::bits::bits(tuple((reserved, stream_id)))(i)
}
