use crate::common::is_offset_safe;
use crate::extractors::common::{Chroot, ExtractionResult, Extractor, ExtractorType};
use crate::structures::cpio::{parse_cpio_entry_header, is_executable, CPIOFileType};
use log::warn;

const EOF_MARKER: &str = "TRAILER!!!";

pub fn cpio_extractor() -> Extractor {
    Extractor {
        utility: ExtractorType::Internal(extract_cpio),
        ..Default::default()
    }
}

pub fn extract_cpio(
    file_data: &[u8],
    offset: usize,
    output_directory: Option<&str>,
) -> ExtractionResult {
    let mut result = ExtractionResult {
        ..Default::default()
    };

    let available_data = file_data.len();
    let mut next_offset = offset;
    let mut previous_offset = None;
    let mut total_size: usize = 0;
    let mut entries: Vec<CPIOEntry> = vec![];

    while is_offset_safe(available_data, next_offset, previous_offset) {
        match file_data.get(next_offset..) {
            None => break,
            Some(entry_data) => {
                match parse_cpio_entry_header(entry_data) {
                    Err(_) => break,
                    Ok(header) => {
                        let entry_total_size = header.header_size + header.data_size;
                        total_size += entry_total_size;

                        if header.file_name == EOF_MARKER {
                            result.success = true;
                            result.size = Some(total_size);
                            break;
                        }

                        let data_offset = next_offset + header.header_size;
                        let data_size = header.data_size;

                        entries.push(CPIOEntry {
                            name: header.file_name.clone(),
                            file_type: header.file_type,
                            mode: header.mode,
                            data_offset,
                            data_size,
                            dev_major: header.dev_major,
                            dev_minor: header.dev_minor,
                        });

                        previous_offset = Some(next_offset);
                        next_offset += entry_total_size;
                    }
                }
            }
        }
    }

    if result.success && output_directory.is_some() {
        let chroot = Chroot::new(output_directory);
        let mut extracted_count: usize = 0;

        for entry in &entries {
            if extract_cpio_entry(file_data, entry, &chroot) {
                extracted_count += 1;
            }
        }

        if extracted_count == 0 {
            result.success = false;
        }
    }

    result
}

#[derive(Debug, Clone)]
struct CPIOEntry {
    name: String,
    file_type: CPIOFileType,
    mode: usize,
    data_offset: usize,
    data_size: usize,
    dev_major: usize,
    dev_minor: usize,
}

fn extract_cpio_entry(file_data: &[u8], entry: &CPIOEntry, chroot: &Chroot) -> bool {
    let file_path = &entry.name;

    let extraction_success = match entry.file_type {
        CPIOFileType::Directory => chroot.create_directory(file_path),
        CPIOFileType::Regular => {
            let actual_size = entry.data_size - calculate_padding(entry.data_size);
            chroot.carve_file(file_path, file_data, entry.data_offset, actual_size)
        }
        CPIOFileType::Symlink => {
            let actual_size = entry.data_size - calculate_padding(entry.data_size);
            if let Some(target_bytes) =
                file_data.get(entry.data_offset..entry.data_offset + actual_size)
            {
                let target_bytes_clean: Vec<u8> = target_bytes
                    .iter()
                    .copied()
                    .take_while(|&b| b != 0)
                    .collect();
                if let Ok(target) = String::from_utf8(target_bytes_clean) {
                    chroot.create_symlink(file_path, target)
                } else {
                    warn!("Failed to parse symlink target for {}", file_path);
                    false
                }
            } else {
                false
            }
        }
        CPIOFileType::Fifo => chroot.create_fifo(file_path),
        CPIOFileType::Socket => chroot.create_socket(file_path),
        CPIOFileType::BlockDevice => {
            chroot.create_block_device(file_path, entry.dev_major, entry.dev_minor)
        }
        CPIOFileType::CharDevice => {
            chroot.create_character_device(file_path, entry.dev_major, entry.dev_minor)
        }
        CPIOFileType::Unknown => {
            warn!("Unknown file type for {}", file_path);
            false
        }
    };

    if extraction_success {
        if entry.file_type == CPIOFileType::Regular && is_executable(entry.mode) {
            chroot.make_executable(file_path);
        }
    } else {
        warn!("Failed to extract CPIO entry: {}", file_path);
    }

    extraction_success
}

fn calculate_padding(size: usize) -> usize {
    let modulus = size % 4;
    if modulus == 0 {
        0
    } else {
        4 - modulus
    }
}
