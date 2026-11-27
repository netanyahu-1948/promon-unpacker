use clap::Parser;

use std::path::{Path, PathBuf};
use std::fs::{self, File};
use std::io::{self, Write};

// mod customer;
mod promon;
mod crypto;

#[derive(Parser)]
#[command(version, about, arg_required_else_help = true)]
struct Args {
    /// Path to the Promon SHIELD native library
    #[arg(value_name = "libpromon.so")]
    libpromon: PathBuf,

    //TODO
    // /// Path to the protected native library
    // #[arg(value_name = "libcustomer.so")]
    // libcustomer: Option<PathBuf>,

    /// Output directory
    #[arg(short, long, default_value = ".")]
    output: PathBuf,
}

fn unpack_library(input: &Path, output: &Path, decrypt: fn(&mut [u8]) -> io::Result<()>) -> io::Result<()> {
    let mut image = fs::read(input)?;
    decrypt(&mut image)?;

    let name = input.file_name().ok_or(io::ErrorKind::InvalidInput)?;
    let path = output.join(name).with_extension("decrypted.so");

    File::create_new(&path)?.write_all(&image)?;

    println!("(promon-unpacker) decrypted library: {}", path.display());
    Ok(())
}

fn main() -> io::Result<()> {
    let args = Args::parse();
    fs::create_dir_all(&args.output)?;

    unpack_library(&args.libpromon, &args.output, promon::decrypt)?;
    //TODO
    // if let Some(path) = &args.libcustomer {
    //     unpack_library(path, &args.output, customer::decrypt)?;
    // }

    Ok(())
}
