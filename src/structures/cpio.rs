use crate::structures::common::StructureError;

/// Expected minimum size of a CPIO entry header
pub const CPIO_HEADER_SIZE: usize = 110;

/// Storage struct for CPIO entry header info
#[derive(Debug, Clone, Default)]
pub struct CPIOEntryHeader {
    pub magic: Vec<u8>,
    pub data_size: usize,
    pub file_name: String,
    pub header_size: usize,
    pub mode: usize,
    pub file_type: CPIOFileType,
    pub dev_major: usize,
    pub dev_minor: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CPIOFileType {
    Regular,
    Directory,
    Symlink,
    BlockDevice,
    CharDevice,
    Fifo,
    Socket,
    Unknown,
}

impl Default for CPIOFileType {
    fn default() -> Self {
        CPIOFileType::Unknown
    }
}

/// Parses a CPIO entry header
pub fn parse_cpio_entry_header(cpio_data: &[u8]) -> Result<CPIOEntryHeader, StructureError> {
    const NULL_BYTE_SIZE: usize = 1;
    const CPIO_MAGIC_START: usize = 0;
    const CPIO_MAGIC_END: usize = 6;
    const MODE_START: usize = 14;
    const MODE_END: usize = 22;
    const DEV_MAJOR_START: usize = 22;
    const DEV_MAJOR_END: usize = 30;
    const DEV_MINOR_START: usize = 30;
    const DEV_MINOR_END: usize = 38;
    const FILE_SIZE_START: usize = 54;
    const FILE_SIZE_END: usize = 62;
    const FILE_NAME_SIZE_START: usize = 94;
    const FILE_NAME_SIZE_END: usize = 102;

    let available_data: usize = cpio_data.len();

    if available_data > CPIO_HEADER_SIZE {
        let header_magic = cpio_data[CPIO_MAGIC_START..CPIO_MAGIC_END].to_vec();

        if let Ok(mode_str) = String::from_utf8(cpio_data[MODE_START..MODE_END].to_vec()) {
            if let Ok(mode) = usize::from_str_radix(&mode_str, 16) {
                if let Ok(dev_major_str) =
                    String::from_utf8(cpio_data[DEV_MAJOR_START..DEV_MAJOR_END].to_vec())
                {
                    if let Ok(dev_major) = usize::from_str_radix(&dev_major_str, 16) {
                        if let Ok(dev_minor_str) =
                            String::from_utf8(cpio_data[DEV_MINOR_START..DEV_MINOR_END].to_vec())
                        {
                            if let Ok(dev_minor) = usize::from_str_radix(&dev_minor_str, 16) {
                                if let Ok(file_data_size_str) =
                                    String::from_utf8(cpio_data[FILE_SIZE_START..FILE_SIZE_END].to_vec())
                                {
                                    if let Ok(file_data_size) = usize::from_str_radix(&file_data_size_str, 16) {
                                        if let Ok(file_name_size_str) =
                                            String::from_utf8(cpio_data[FILE_NAME_SIZE_START..FILE_NAME_SIZE_END].to_vec())
                                        {
                                            if let Ok(file_name_size) = usize::from_str_radix(&file_name_size_str, 16) {
                                                let file_name_start: usize = CPIO_HEADER_SIZE;
                                                let file_name_end: usize =
                                                    file_name_start + file_name_size - NULL_BYTE_SIZE;

                                                if let Some(file_name_raw_bytes) =
                                                    cpio_data.get(file_name_start..file_name_end)
                                                {
                                                    if let Ok(file_name) = String::from_utf8(file_name_raw_bytes.to_vec()) {
                                                        let header_total_size = CPIO_HEADER_SIZE + file_name_size;
                                                        let file_type = parse_file_type(mode);

                                                        return Ok(CPIOEntryHeader {
                                                            magic: header_magic.clone(),
                                                            file_name: file_name.clone(),
                                                            data_size: file_data_size + byte_padding(file_data_size),
                                                            header_size: header_total_size
                                                                + byte_padding(header_total_size),
                                                            mode,
                                                            file_type,
                                                            dev_major,
                                                            dev_minor,
                                                        });
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Err(StructureError)
}

fn byte_padding(n: usize) -> usize {
    let modulus: usize = n % 4;
    if modulus == 0 { 0 } else { 4 - modulus }
}

fn parse_file_type(mode: usize) -> CPIOFileType {
    const S_IFMT: usize = 0o170000;
    const S_IFREG: usize = 0o100000;
    const S_IFDIR: usize = 0o040000;
    const S_IFLNK: usize = 0o120000;
    const S_IFBLK: usize = 0o060000;
    const S_IFCHR: usize = 0o020000;
    const S_IFIFO: usize = 0o010000;
    const S_IFSOCK: usize = 0o140000;

    match mode & S_IFMT {
        S_IFREG => CPIOFileType::Regular,
        S_IFDIR => CPIOFileType::Directory,
        S_IFLNK => CPIOFileType::Symlink,
        S_IFBLK => CPIOFileType::BlockDevice,
        S_IFCHR => CPIOFileType::CharDevice,
        S_IFIFO => CPIOFileType::Fifo,
        S_IFSOCK => CPIOFileType::Socket,
        _ => CPIOFileType::Unknown,
    }
}

pub fn is_executable(mode: usize) -> bool {
    const S_IXUSR: usize = 0o100;
    const S_IXGRP: usize = 0o010;
    const S_IXOTH: usize = 0o001;
    (mode & (S_IXUSR | S_IXGRP | S_IXOTH)) != 0
}
