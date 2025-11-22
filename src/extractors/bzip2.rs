use crate::extractors::common::{Chroot, ExtractionResult, Extractor, ExtractorType};
use bzip2::read::BzDecoder;
use std::io::{Cursor, Read};

/// Defines the internal extractor function for decompressing BZIP2 files
///
/// ```
/// use std::io::ErrorKind;
/// use std::process::Command;
/// use binwalk::extractors::common::ExtractorType;
/// use binwalk::extractors::bzip2::bzip2_extractor;
///
/// match bzip2_extractor().utility {
///     ExtractorType::None => panic!("Invalid extractor type of None"),
///     ExtractorType::Internal(func) => println!("Internal extractor OK: {:?}", func),
///     ExtractorType::External(cmd) => {
///         if let Err(e) = Command::new(&cmd).output() {
///             if e.kind() == ErrorKind::NotFound {
///                 panic!("External extractor '{}' not found", cmd);
///             } else {
///                 panic!("Failed to execute external extractor '{}': {}", cmd, e);
///             }
///         }
///     }
/// }
/// ```
pub fn bzip2_extractor() -> Extractor {
    Extractor {
        utility: ExtractorType::Internal(bzip2_decompressor),
        ..Default::default()
    }
}


/// Internal extractor for decompressing BZIP2 data
pub fn bzip2_decompressor(
    file_data: &[u8],
    offset: usize,
    output_directory: Option<&str>,
) -> ExtractionResult {
    // Size of streaming buffer
    const READ_BUF_SIZE: usize = 64 * 1024;
    // Output file for decompressed data
    const OUTPUT_FILE_NAME: &str = "decompressed.bin";

    let mut result = ExtractionResult::default();

    // Nothing to do if offset is past EOF
    if offset >= file_data.len() {
        return result;
    }

    let mut total_consumed: usize = 0;
    let mut any_decompressed = false;
    let mut current_offset = offset;

    // Loop to handle concatenated bzip2 members
    loop {
        if current_offset >= file_data.len() {
            break;
        }

        let slice = &file_data[current_offset..];
        let cursor = Cursor::new(slice);
        let mut decoder = BzDecoder::new(cursor);
        let mut read_buf = [0u8; READ_BUF_SIZE];
        let mut any_output_this_member = false;

        loop {
            match decoder.read(&mut read_buf) {
                Ok(0) => {
                    // EOF for this member (or no output right now)
                    break;
                }
                Ok(n) => {
                    any_output_this_member = true;

                    // If extraction requested, append this decoded chunk
                    if output_directory.is_some() {
                        let chroot = Chroot::new(output_directory);
                        if !chroot.append_to_file(OUTPUT_FILE_NAME, &read_buf[..n]) {
                            // Writing failed; stop everything and return what we have so far
                            result.success = any_decompressed;
                            result.size = Some(total_consumed);
                            return result;
                        }
                    }
                }
                Err(_) => {
                    // Decompression error for this member -> stop processing
                    result.success = any_decompressed;
                    result.size = Some(total_consumed);
                    return result;
                }
            }
        }

        let cursor = decoder.into_inner();
        let consumed = cursor.position() as usize;

        // If the decoder consumed zero bytes, stop to avoid infinite loop.
        if consumed == 0 {
            break;
        }

        current_offset += consumed;
        total_consumed += consumed;

        if any_output_this_member {
            any_decompressed = true;
        }
    }

    result.success = any_decompressed;
    result.size = if total_consumed > 0 { Some(total_consumed) } else { None };

    result
}
