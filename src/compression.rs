use super::result::Result;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use std::io::{Read, Write};

pub trait Decompress {
    fn compress(&self, in_buffer: &[u8]) -> Result<Vec<u8>>;
    fn decompress(&self, in_buffer: &[u8]) -> Result<Vec<u8>>;
}

pub struct NoCompression;

impl Decompress for NoCompression {
    fn compress(&self, in_buffer: &[u8]) -> Result<Vec<u8>> {
        Ok(in_buffer.to_vec())
    }
    fn decompress(&self, in_buffer: &[u8]) -> Result<Vec<u8>> {
        Ok(in_buffer.to_vec())
    }
}

pub struct GZipCompression;

impl Decompress for GZipCompression {
    fn compress(&self, in_buffer: &[u8]) -> Result<Vec<u8>> {
        let mut res = Vec::new();
        let mut encoder = GzEncoder::new(&mut res, Compression::default());
        encoder.write_all(in_buffer)?;
        encoder.flush()?;
        encoder.finish()?;
        Ok(res)
    }
    fn decompress(&self, in_buffer: &[u8]) -> Result<Vec<u8>> {
        let mut res = Vec::new();
        let mut decoder = GzDecoder::new(in_buffer);
        decoder.read_to_end(&mut res)?;
        Ok(res)
    }
}
