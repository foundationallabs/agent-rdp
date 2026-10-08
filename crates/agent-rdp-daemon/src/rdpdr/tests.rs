//! Drive-confinement tests that drive each path-taking request through the backend.

use std::fs;
use std::path::{Path, PathBuf};

use ironrdp_rdpdr::pdu::efs::*;
use ironrdp_rdpdr::RdpdrBackend;
use ironrdp_svc::SvcMessage;

use super::MultiDriveBackend;

const DEVICE_ID: u32 = 7;
/// Handle of the drive root, opened in the fixture; directory queries run against it.
const ROOT_HANDLE: u32 = 100;

/// A temp folder holding the drive (`drive/`) and a sibling the server must not reach (`outside/`).
struct Fixture {
    _root: tempfile::TempDir,
    drive: PathBuf,
    outside: PathBuf,
    backend: MultiDriveBackend,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let drive = root.path().join("drive");
        let outside = root.path().join("outside");
        fs::create_dir_all(drive.join("sub")).unwrap();
        fs::write(drive.join("sub").join("file.txt"), b"inside").unwrap();
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("secret.txt"), b"secret").unwrap();
        let mut backend = MultiDriveBackend::new();
        backend.add_drive(DEVICE_ID, drive.clone());
        backend.file_id = ROOT_HANDLE + 1;
        backend.insert_directory(ROOT_HANDLE, DEVICE_ID, drive.clone());
        Self {
            _root: root,
            drive,
            outside,
            backend,
        }
    }

    fn create(&mut self, path: &str, disposition: CreateDisposition) -> (NtStatus, u32) {
        let file_id = self.backend.file_id;
        let messages = self
            .backend
            .handle_drive_io_request(ServerDriveIoRequest::ServerCreateDriveRequest(
                DeviceCreateRequest {
                    device_io_request: io_request(MajorFunction::Create, MinorFunction::from(0), 0),
                    desired_access: DesiredAccess::GENERIC_ALL,
                    allocation_size: 0,
                    file_attributes: FileAttributes::empty(),
                    shared_access: SharedAccess::FILE_SHARE_READ,
                    create_disposition: disposition,
                    create_options: CreateOptions::FILE_NON_DIRECTORY_FILE,
                    path: path.to_owned(),
                },
            ))
            .unwrap();
        (io_status(&messages), file_id)
    }

    fn query_directory(&mut self, path: &str) -> NtStatus {
        self.query_directory_as(
            &FileInformationClassLevel::FILE_BOTH_DIRECTORY_INFORMATION,
            path,
        )
    }

    fn query_directory_as(&mut self, class: &FileInformationClassLevel, path: &str) -> NtStatus {
        io_status(&self.directory_request(class, true, path))
    }

    /// Send one IRP_MN_QUERY_DIRECTORY against the drive root handle and return the raw response.
    fn directory_request(
        &mut self,
        class: &FileInformationClassLevel,
        initial: bool,
        path: &str,
    ) -> Vec<SvcMessage> {
        self.backend
            .handle_drive_io_request(ServerDriveIoRequest::ServerDriveQueryDirectoryRequest(
                ServerDriveQueryDirectoryRequest {
                    device_io_request: io_request(
                        MajorFunction::DirectoryControl,
                        MinorFunction::IRP_MN_QUERY_DIRECTORY,
                        ROOT_HANDLE,
                    ),
                    file_info_class_lvl: class.clone(),
                    initial_query: u8::from(initial),
                    // Continuation requests carry no path (MS-RDPEFS 2.2.3.3.10).
                    path: if initial {
                        path.to_owned()
                    } else {
                        String::new()
                    },
                },
            ))
            .unwrap()
    }

    fn read(&mut self, file_id: u32, offset: u64, length: u32) -> (NtStatus, Vec<u8>) {
        let messages = self
            .backend
            .handle_drive_io_request(ServerDriveIoRequest::DeviceReadRequest(DeviceReadRequest {
                device_io_request: io_request(MajorFunction::Read, MinorFunction::from(0), file_id),
                length,
                offset,
            }))
            .unwrap();
        let bytes = messages[0].encode_unframed_pdu().unwrap();
        // DR_READ_RSP: DeviceIoResponse (16 with the RDPDR header), Length (4), ReadData.
        let len = u32::from_le_bytes(bytes[16..20].try_into().unwrap()) as usize;
        (io_status(&messages), bytes[20..20 + len].to_vec())
    }

    fn rename(&mut self, file_id: u32, to: &str) -> NtStatus {
        let messages = self
            .backend
            .handle_drive_io_request(ServerDriveIoRequest::ServerDriveSetInformationRequest(
                ServerDriveSetInformationRequest {
                    device_io_request: io_request(
                        MajorFunction::SetInformation,
                        MinorFunction::from(0),
                        file_id,
                    ),
                    set_buffer: FileInformationClass::Rename(FileRenameInformation {
                        replace_if_exists: Boolean::False,
                        file_name: to.to_owned(),
                    }),
                },
            ))
            .unwrap();
        io_status(&messages)
    }

    fn opened_outside_the_drive(&self) -> bool {
        self.backend
            .file_path_map
            .values()
            .any(|path| !path.starts_with(&self.drive))
            || self
                .backend
                .file_dir_map
                .values()
                .any(|state| !state.base_path.starts_with(&self.drive))
    }
}

fn io_request(
    major_function: MajorFunction,
    minor_function: MinorFunction,
    file_id: u32,
) -> DeviceIoRequest {
    DeviceIoRequest {
        device_id: DEVICE_ID,
        file_id,
        completion_id: 1,
        major_function,
        minor_function,
    }
}

/// Read IoStatus from the single response: RDPDR header (4) + DeviceId (4) + CompletionId (4).
fn io_status(messages: &[SvcMessage]) -> NtStatus {
    assert_eq!(messages.len(), 1);
    let bytes = messages[0].encode_unframed_pdu().unwrap();
    NtStatus::from(u32::from_le_bytes(bytes[12..16].try_into().unwrap()))
}

fn assert_untouched(outside: &Path) {
    let mut names: Vec<_> = fs::read_dir(outside)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    names.sort();
    assert_eq!(names, ["secret.txt"]);
    assert_eq!(fs::read(outside.join("secret.txt")).unwrap(), b"secret");
}

#[test]
fn create_opens_inside_and_denies_escapes() {
    let mut fx = Fixture::new();
    assert_eq!(
        fx.create("\\sub\\file.txt", CreateDisposition::FILE_OPEN).0,
        NtStatus::SUCCESS
    );

    for path in [
        "..\\outside\\secret.txt",
        "\\sub\\..\\..\\outside\\secret.txt",
        "C:\\x",
        "sub\\file.txt:ads",
    ] {
        assert_eq!(
            fx.create(path, CreateDisposition::FILE_OPEN).0,
            NtStatus::ACCESS_DENIED,
            "{path:?}"
        );
    }
    assert_eq!(
        fx.create("..\\outside\\new.txt", CreateDisposition::FILE_CREATE)
            .0,
        NtStatus::ACCESS_DENIED
    );

    assert!(!fx.opened_outside_the_drive());
    assert_untouched(&fx.outside);
}

#[cfg(unix)]
#[test]
fn create_denies_a_symlink_inside_the_drive() {
    let mut fx = Fixture::new();
    std::os::unix::fs::symlink("/", fx.drive.join("root")).unwrap();
    std::os::unix::fs::symlink(&fx.outside, fx.drive.join("sub").join("out")).unwrap();

    assert_eq!(
        fx.create("\\root\\etc\\hosts", CreateDisposition::FILE_OPEN)
            .0,
        NtStatus::ACCESS_DENIED
    );
    assert_eq!(
        fx.create("\\sub\\out\\secret.txt", CreateDisposition::FILE_OPEN)
            .0,
        NtStatus::ACCESS_DENIED
    );
    assert_eq!(
        fx.create("\\sub\\out\\new.txt", CreateDisposition::FILE_CREATE)
            .0,
        NtStatus::ACCESS_DENIED
    );
    assert!(!fx.opened_outside_the_drive());
    assert_untouched(&fx.outside);
}

#[test]
fn file_query_denies_escapes() {
    let mut fx = Fixture::new();
    assert_eq!(fx.query_directory("\\sub\\file.txt"), NtStatus::SUCCESS);
    assert_eq!(
        fx.query_directory("..\\outside\\secret.txt"),
        NtStatus::ACCESS_DENIED
    );
}

#[test]
fn wildcard_query_denies_escapes() {
    let mut fx = Fixture::new();
    assert_eq!(fx.query_directory("\\sub\\*"), NtStatus::SUCCESS);
    assert_eq!(fx.query_directory("..\\*"), NtStatus::ACCESS_DENIED);
    assert_eq!(
        fx.query_directory("..\\outside\\*"),
        NtStatus::ACCESS_DENIED
    );
    assert!(!fx.opened_outside_the_drive());
}

#[test]
fn rename_denies_a_target_outside_the_drive() {
    let mut fx = Fixture::new();
    let (status, file_id) = fx.create("\\sub\\file.txt", CreateDisposition::FILE_OPEN);
    assert_eq!(status, NtStatus::SUCCESS);

    assert_eq!(
        fx.rename(file_id, "..\\outside\\moved.txt"),
        NtStatus::ACCESS_DENIED
    );
    assert_eq!(
        fx.rename(file_id, "\\sub\\..\\..\\outside\\moved.txt"),
        NtStatus::ACCESS_DENIED
    );
    assert!(fx.drive.join("sub").join("file.txt").exists());
    assert_untouched(&fx.outside);

    assert_eq!(fx.rename(file_id, "\\sub\\renamed.txt"), NtStatus::SUCCESS);
    assert!(fx.drive.join("sub").join("renamed.txt").exists());
}

// Directory queries and reads: the information classes Windows sends for `dir`, `type` and `copy`.

/// The four classes MS-RDPEFS 2.2.3.3.10 allows in a drive directory query.
const DIRECTORY_CLASSES: [FileInformationClassLevel; 4] = [
    FileInformationClassLevel::FILE_DIRECTORY_INFORMATION,
    FileInformationClassLevel::FILE_FULL_DIRECTORY_INFORMATION,
    FileInformationClassLevel::FILE_BOTH_DIRECTORY_INFORMATION,
    FileInformationClassLevel::FILE_NAMES_INFORMATION,
];

/// Byte offsets of `FileNameLength` and `FileName` within one entry of `class`.
///
/// MS-FSCC 2.4.10 / 2.4.14 / 2.4.28. `FileBothDirectoryInformation` follows the FreeRDP wire
/// form ironrdp encodes (no `Reserved1` byte), which puts `FileName` at 93 instead of 94.
fn name_offsets(class: &FileInformationClassLevel) -> (usize, usize) {
    match *class {
        FileInformationClassLevel::FILE_DIRECTORY_INFORMATION => (60, 64),
        FileInformationClassLevel::FILE_FULL_DIRECTORY_INFORMATION => (60, 68),
        FileInformationClassLevel::FILE_BOTH_DIRECTORY_INFORMATION => (60, 93),
        FileInformationClassLevel::FILE_NAMES_INFORMATION => (8, 12),
        _ => panic!("not a directory class: {class:?}"),
    }
}

/// Split a DR_DRIVE_QUERY_DIRECTORY_RSP into its status and entry buffer.
fn directory_entry_bytes(messages: &[SvcMessage]) -> (NtStatus, Vec<u8>) {
    let status = io_status(messages);
    let bytes = messages[0].encode_unframed_pdu().unwrap();
    let len = u32::from_le_bytes(bytes[16..20].try_into().unwrap()) as usize;
    if len == 0 {
        // An empty buffer is followed by one padding byte.
        assert_eq!(bytes.len(), 21);
    } else {
        assert_eq!(bytes.len(), 20 + len, "Length must cover exactly the entry");
    }
    (status, bytes[20..20 + len].to_vec())
}

fn u32_at(buf: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(buf[at..at + 4].try_into().unwrap())
}

fn i64_at(buf: &[u8], at: usize) -> i64 {
    i64::from_le_bytes(buf[at..at + 8].try_into().unwrap())
}

/// Decode the entry's name and check the entry is exactly the fixed part plus the name.
fn entry_name(class: &FileInformationClassLevel, entry: &[u8]) -> String {
    let (len_at, name_at) = name_offsets(class);
    let name_len = u32_at(entry, len_at) as usize;
    assert_eq!(
        entry.len(),
        name_at + name_len,
        "no padding after a sole entry"
    );
    let units: Vec<u16> = entry[name_at..]
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16(&units).unwrap()
}

fn filetime(secs_since_unix_epoch: u64) -> i64 {
    i64::try_from(secs_since_unix_epoch).unwrap() * 10_000_000 + 116_444_736_000_000_000
}

#[test]
fn each_directory_class_encodes_the_ms_fscc_layout() {
    const ACCESSED: u64 = 1_700_000_000;
    const MODIFIED: u64 = 1_600_000_000;
    let mut fx = Fixture::new();
    let name = "héllo wörld.txt";
    let path = fx.drive.join(name);
    fs::write(&path, b"0123456789AB").unwrap();
    fs::File::options()
        .write(true)
        .open(&path)
        .unwrap()
        .set_times(
            fs::FileTimes::new()
                .set_accessed(std::time::UNIX_EPOCH + std::time::Duration::from_secs(ACCESSED))
                .set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(MODIFIED)),
        )
        .unwrap();

    for class in &DIRECTORY_CLASSES {
        let (status, entry) =
            directory_entry_bytes(&fx.directory_request(class, true, &format!("\\{name}")));
        assert_eq!(status, NtStatus::SUCCESS, "{class:?}");

        assert_eq!(
            u32_at(&entry, 0),
            0,
            "{class:?}: NextEntryOffset of the sole entry"
        );
        assert_eq!(u32_at(&entry, 4), 0, "{class:?}: FileIndex");
        let (len_at, _) = name_offsets(class);
        assert_eq!(
            u32_at(&entry, len_at) as usize,
            name.encode_utf16().count() * 2
        );
        assert_eq!(entry_name(class, &entry), name, "{class:?}");

        if *class == FileInformationClassLevel::FILE_NAMES_INFORMATION {
            continue;
        }
        assert_eq!(
            i64_at(&entry, 16),
            filetime(ACCESSED),
            "{class:?}: LastAccessTime"
        );
        assert_eq!(
            i64_at(&entry, 24),
            filetime(MODIFIED),
            "{class:?}: LastWriteTime"
        );
        assert_eq!(
            i64_at(&entry, 32),
            filetime(MODIFIED),
            "{class:?}: ChangeTime"
        );
        assert_eq!(i64_at(&entry, 40), 12, "{class:?}: EndOfFile");
        assert_eq!(i64_at(&entry, 48), 12, "{class:?}: AllocationSize");
        assert_eq!(
            u32_at(&entry, 56),
            FileAttributes::FILE_ATTRIBUTE_ARCHIVE.bits(),
            "{class:?}: FileAttributes"
        );
        if *class != FileInformationClassLevel::FILE_DIRECTORY_INFORMATION {
            assert_eq!(u32_at(&entry, 64), 0, "{class:?}: EaSize");
        }
    }
}

#[test]
fn a_directory_entry_is_flagged_as_a_directory() {
    let mut fx = Fixture::new();
    for class in &DIRECTORY_CLASSES {
        let (status, entry) = directory_entry_bytes(&fx.directory_request(class, true, "\\sub"));
        assert_eq!(status, NtStatus::SUCCESS, "{class:?}");
        assert_eq!(entry_name(class, &entry), "sub");
        if *class != FileInformationClassLevel::FILE_NAMES_INFORMATION {
            assert_eq!(
                u32_at(&entry, 56),
                FileAttributes::FILE_ATTRIBUTE_DIRECTORY.bits(),
                "{class:?}"
            );
        }
    }
}

#[test]
fn enumeration_returns_every_entry_then_no_more_files() {
    let mut fx = Fixture::new();
    let many = fx.drive.join("many");
    fs::create_dir(&many).unwrap();
    let mut expected: Vec<String> = (0..40).map(|i| format!("file-{i:02}.txt")).collect();
    for name in &expected {
        fs::write(many.join(name), name.as_bytes()).unwrap();
    }
    fs::create_dir(many.join("nested")).unwrap();
    expected.push("nested".to_owned());
    expected.sort();

    for class in &DIRECTORY_CLASSES {
        let mut seen = Vec::new();
        let (status, entry) =
            directory_entry_bytes(&fx.directory_request(class, true, "\\many\\*"));
        assert_eq!(status, NtStatus::SUCCESS, "{class:?}");
        seen.push(entry_name(class, &entry));
        loop {
            let (status, entry) = directory_entry_bytes(&fx.directory_request(class, false, ""));
            if status == NtStatus::NO_MORE_FILES {
                assert!(entry.is_empty());
                break;
            }
            assert_eq!(status, NtStatus::SUCCESS, "{class:?}");
            assert_eq!(u32_at(&entry, 0), 0, "{class:?}: NextEntryOffset");
            seen.push(entry_name(class, &entry));
            assert!(
                seen.len() <= expected.len(),
                "{class:?}: enumeration did not end"
            );
        }
        seen.sort();
        assert_eq!(seen, expected, "{class:?}");
    }
}

#[test]
fn an_empty_directory_enumerates_nothing() {
    let mut fx = Fixture::new();
    fs::create_dir(fx.drive.join("empty")).unwrap();
    for class in &DIRECTORY_CLASSES {
        let (status, entry) =
            directory_entry_bytes(&fx.directory_request(class, true, "\\empty\\*"));
        assert_eq!(status, NtStatus::NO_SUCH_FILE, "{class:?}");
        assert!(entry.is_empty());
        let (status, entry) = directory_entry_bytes(&fx.directory_request(class, false, ""));
        assert_eq!(status, NtStatus::NO_MORE_FILES, "{class:?}");
        assert!(entry.is_empty());
    }
}

#[test]
fn a_missing_file_query_is_no_such_file() {
    let mut fx = Fixture::new();
    for class in &DIRECTORY_CLASSES {
        assert_eq!(
            fx.query_directory_as(class, "\\sub\\absent.txt"),
            NtStatus::NO_SUCH_FILE,
            "{class:?}"
        );
    }
}

#[test]
fn a_class_outside_the_directory_set_is_not_supported() {
    let mut fx = Fixture::new();
    assert_eq!(
        fx.query_directory_as(&FileInformationClassLevel::FILE_BASIC_INFORMATION, "\\sub"),
        NtStatus::NOT_SUPPORTED
    );
}

#[test]
fn every_directory_class_denies_escapes() {
    let mut fx = Fixture::new();
    for class in &DIRECTORY_CLASSES {
        for path in [
            "..\\outside\\secret.txt",
            "\\sub\\..\\..\\outside\\secret.txt",
            "..\\*",
            "..\\outside\\*",
            "\\sub\\..\\..\\outside\\*",
        ] {
            assert_eq!(
                fx.query_directory_as(class, path),
                NtStatus::ACCESS_DENIED,
                "{class:?} {path:?}"
            );
        }
    }
    assert!(!fx.opened_outside_the_drive());
}

#[cfg(unix)]
#[test]
fn every_directory_class_denies_a_symlink_inside_the_drive() {
    let mut fx = Fixture::new();
    std::os::unix::fs::symlink(&fx.outside, fx.drive.join("out")).unwrap();
    for class in &DIRECTORY_CLASSES {
        assert_eq!(
            fx.query_directory_as(class, "\\out\\secret.txt"),
            NtStatus::ACCESS_DENIED,
            "{class:?}"
        );
        assert_eq!(
            fx.query_directory_as(class, "\\out\\*"),
            NtStatus::ACCESS_DENIED,
            "{class:?}"
        );
    }
    assert!(!fx.opened_outside_the_drive());
}

#[test]
fn read_returns_the_file_bytes_and_nothing_past_eof() {
    let mut fx = Fixture::new();
    let (status, file_id) = fx.create("\\sub\\file.txt", CreateDisposition::FILE_OPEN);
    assert_eq!(status, NtStatus::SUCCESS);

    assert_eq!(
        fx.read(file_id, 0, 4096),
        (NtStatus::SUCCESS, b"inside".to_vec())
    );
    assert_eq!(fx.read(file_id, 2, 3), (NtStatus::SUCCESS, b"sid".to_vec()));
    // Past EOF: success with no data, as FreeRDP and mstsc answer; the server's redirector
    // turns a zero-length read into STATUS_END_OF_FILE for the caller.
    assert_eq!(fx.read(file_id, 6, 4096), (NtStatus::SUCCESS, Vec::new()));
    assert_eq!(
        fx.read(file_id, 1 << 20, 16),
        (NtStatus::SUCCESS, Vec::new())
    );
}

#[test]
fn write_at_an_offset_overwrites_in_place() {
    // FILE_OPEN_IF, as cmd sends for `>>`; FILE_OPEN opens read-only today regardless of DesiredAccess.
    let mut fx = Fixture::new();
    let (status, file_id) = fx.create("\\sub\\file.txt", CreateDisposition::FILE_OPEN_IF);
    assert_eq!(status, NtStatus::SUCCESS);
    let messages = fx
        .backend
        .handle_drive_io_request(ServerDriveIoRequest::DeviceWriteRequest(
            DeviceWriteRequest {
                device_io_request: io_request(
                    MajorFunction::Write,
                    MinorFunction::from(0),
                    file_id,
                ),
                offset: 2,
                write_data: b"SID".to_vec(),
            },
        ))
        .unwrap();
    assert_eq!(io_status(&messages), NtStatus::SUCCESS);
    assert_eq!(
        fx.read(file_id, 0, 4096),
        (NtStatus::SUCCESS, b"inSIDe".to_vec())
    );
}
