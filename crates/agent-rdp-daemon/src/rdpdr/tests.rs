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
        let messages = self
            .backend
            .handle_drive_io_request(ServerDriveIoRequest::ServerDriveQueryDirectoryRequest(
                ServerDriveQueryDirectoryRequest {
                    device_io_request: io_request(
                        MajorFunction::DirectoryControl,
                        MinorFunction::IRP_MN_QUERY_DIRECTORY,
                        ROOT_HANDLE,
                    ),
                    file_info_class_lvl: FileInformationClassLevel::FILE_BOTH_DIRECTORY_INFORMATION,
                    initial_query: 1,
                    path: path.to_owned(),
                },
            ))
            .unwrap();
        io_status(&messages)
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
