use base64::{engine::general_purpose, Engine as _};
use clap::Parser;
use openssl::symm::{decrypt, Cipher};
use serde_json::Value;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::Path;

static MAGIC: &[u8; 8] = b"CTENFDAM";
static CORE_KEY: &[u8; 16] = b"hzHRAmso5kInbaxW";
static META_KEY: &[u8; 16] = b"#14ljk_!\\]&0U<'(";

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// ncm files or folders
    files: Vec<String>,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    for path in args.files {
        dump(Path::new(&path))?;
    }
    Ok(())
}

fn dump(path: &Path) -> anyhow::Result<()> {
    if !path.exists() {
        return Ok(());
    }
    if path.is_dir() {
        for entry in path.read_dir()? {
            let entry = entry?;
            let file_path = entry.path();
            dump(&file_path)?;
        }
    } else if path.extension().unwrap() == "ncm" {
        dump_file(&path)?;
    }
    Ok(())
}

fn dump_file(path: &Path) -> anyhow::Result<()> {
    let mut file = read_ncm(path)?;
    let key_data = read_key_data(&mut file)?;
    let meta_data = read_meta_data(&mut file)?;
    seek_to_music(&mut file)?;
    // let crc32 = read_crc32(&mut file)?;
    // let image_data = read_image_data(&mut file)?;
    let extension = meta_data["format"].as_str().unwrap();
    let dump_path = Path::new(path).with_extension(extension);
    println!("dump: {:?}", dump_path);
    let dump_file = File::create(dump_path)?;
    let mut dump_file = BufWriter::new(dump_file);
    loop {
        let mut buffer = vec![0u8; 0x8000];
        let size = file.read(&mut buffer)?;
        if size == 0 {
            break;
        }
        for i in 0..size {
            let j = (i + 1) & 0xff;
            let k = (key_data[j] as usize + j) & 0xff;
            let l = (key_data[j] as usize + key_data[k] as usize) & 0xff;
            buffer[i] ^= key_data[l];
        }
        dump_file.write(&buffer[..size])?;
    }
    Ok(())
}

fn read_ncm(path: &Path) -> anyhow::Result<BufReader<File>> {
    let file = File::open(path)?;
    let mut file = BufReader::new(file);
    let mut header = vec![0u8; 8];
    file.read_exact(&mut header)?;
    assert_eq!(header, MAGIC, "not a ncm file");
    file.seek(SeekFrom::Current(2))?;
    Ok(file)
}

fn read_key_data(file: &mut BufReader<File>) -> anyhow::Result<Vec<u8>> {
    let mut key_length = vec![0u8; 4];
    file.read_exact(&mut key_length)?;
    let key_length = key_length.try_into().unwrap();
    let key_length = u32::from_le_bytes(key_length) as usize;
    let mut key_data = vec![0u8; key_length];
    file.read_exact(&mut key_data)?;
    for i in 0..key_length {
        key_data[i] ^= 0x64;
    }
    let key_data = decrypt(Cipher::aes_128_ecb(), CORE_KEY, None, &key_data)?;
    Ok(convert_key_data(&key_data))
}

fn convert_key_data(key_data: &Vec<u8>) -> Vec<u8> {
    let key_data = &key_data[17..];
    let key_length = key_data.len();
    let mut key_box: Vec<u8> = (0..255).collect();
    key_box.push(255);
    let mut last_byte = 0u8;
    let mut key_offset = 0;
    for i in 0..256 {
        let swap = key_box[i];
        let c = (swap as u16 + last_byte as u16 + key_data[key_offset] as u16) as u8 & 0xff;
        key_offset += 1;
        if key_offset >= key_length {
            key_offset = 0;
        }
        key_box[i] = key_box[c as usize];
        key_box[c as usize] = swap;
        last_byte = c;
    }
    key_box
}

fn read_meta_data(file: &mut BufReader<File>) -> anyhow::Result<Value> {
    let mut meta_length = vec![0u8; 4];
    file.read_exact(&mut meta_length)?;
    let meta_length = u32::from_le_bytes(meta_length.try_into().unwrap()) as usize;
    let mut meta_data = vec![0u8; meta_length];
    file.read_exact(&mut meta_data)?;
    for i in 0..meta_length {
        meta_data[i] ^= 0x63;
    }
    let meta_data = general_purpose::STANDARD.decode(&meta_data[22..]).unwrap();
    let meta_data = decrypt(Cipher::aes_128_ecb(), META_KEY, None, &meta_data)?;
    convert_meta_data(&meta_data)
}

fn convert_meta_data(meta_data: &Vec<u8>) -> anyhow::Result<Value> {
    let meta_data = String::from_utf8(meta_data[6..].to_vec())?;
    Ok(serde_json::from_str(&meta_data)?)
}

#[allow(dead_code)]
fn read_crc32(file: &mut BufReader<File>) -> anyhow::Result<u32> {
    let mut crc32 = vec![0u8; 4];
    file.read_exact(&mut crc32)?;
    let crc32 = u32::from_le_bytes(crc32.try_into().unwrap());
    file.seek(SeekFrom::Current(5))?;
    Ok(crc32)
}

#[allow(dead_code)]
fn read_image_data(file: &mut BufReader<File>) -> anyhow::Result<Vec<u8>> {
    let mut image_size = vec![0u8; 4];
    file.read_exact(&mut image_size)?;
    let image_size = u32::from_le_bytes(image_size.try_into().unwrap());
    let mut image_data = vec![0u8; image_size as usize];
    file.read_exact(&mut image_data)?;
    Ok(image_data)
}

fn seek_to_music(file: &mut BufReader<File>) -> anyhow::Result<()> {
    file.seek(SeekFrom::Current(9))?;
    let mut image_size = vec![0u8; 4];
    file.read_exact(&mut image_size)?;
    let image_size = u32::from_le_bytes(image_size.try_into().unwrap());
    file.seek(SeekFrom::Current(image_size as i64))?;
    Ok(())
}
