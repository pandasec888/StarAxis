#![doc = "Thin, vault-independent Native Messaging bridge for StarAxis."]
#![forbid(unsafe_code)]

use std::io;
use std::path::Path;

#[cfg(not(windows))]
use interprocess::local_socket::GenericFilePath;
#[cfg(windows)]
use interprocess::local_socket::GenericNamespaced;
use interprocess::local_socket::{Stream, prelude::*};
use vault_extension_protocol::{
    ClientRequest, ErrorCode, HostRequest, HostResponse, MAX_FRAME_BYTES, local_endpoint_name,
};

fn main() {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let caller_origin = caller_origin(&arguments)
        .or_else(|| std::env::var("STARAXIS_CALLER_ORIGIN").ok())
        .unwrap_or_default();
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut reader = stdin.lock();
    let mut writer = stdout.lock();
    loop {
        let request_bytes = match read_native_frame(&mut reader) {
            Ok(Some(bytes)) => bytes,
            Ok(None) => break,
            Err(_) => {
                let _ = write_native_response(
                    &mut writer,
                    &HostResponse::error(ErrorCode::InvalidRequest, "invalid native message"),
                );
                break;
            }
        };
        let response = serde_json::from_slice::<ClientRequest>(&request_bytes).map_or_else(
            |_| HostResponse::error(ErrorCode::InvalidRequest, "invalid native request"),
            |request| forward(&caller_origin, request),
        );
        if write_native_response(&mut writer, &response).is_err() {
            break;
        }
    }
}

fn caller_origin(arguments: &[String]) -> Option<String> {
    let first = arguments.first()?;
    if first.starts_with("chrome-extension://") || first.starts_with("moz-extension://") {
        return Some(first.clone());
    }
    arguments
        .get(1)
        .filter(|id| !id.is_empty() && !id.contains('|'))
        .map(|id| format!("firefox-extension://{id}"))
}

fn forward(caller_origin: &str, request: ClientRequest) -> HostResponse {
    let Some(endpoint) = local_endpoint_name() else {
        return HostResponse::error(ErrorCode::DesktopOffline, "StarAxis桌面端未运行");
    };
    #[cfg(windows)]
    let name = match endpoint.to_ns_name::<GenericNamespaced>() {
        Ok(name) => name,
        Err(_) => return HostResponse::error(ErrorCode::DesktopOffline, "StarAxis桌面端未运行"),
    };
    #[cfg(not(windows))]
    let name = match Path::new(&endpoint).to_fs_name::<GenericFilePath>() {
        Ok(name) => name,
        Err(_) => return HostResponse::error(ErrorCode::DesktopOffline, "StarAxis桌面端未运行"),
    };
    let mut stream = match Stream::connect(name) {
        Ok(stream) => stream,
        Err(_) => return HostResponse::error(ErrorCode::DesktopOffline, "StarAxis桌面端未运行"),
    };
    let host_request = HostRequest {
        caller_origin: caller_origin.to_owned(),
        request,
    };
    let bytes = match serde_json::to_vec(&host_request) {
        Ok(bytes) => bytes,
        Err(_) => return HostResponse::error(ErrorCode::InvalidRequest, "请求无法编码"),
    };
    if write_internal_frame(&mut stream, &bytes).is_err() {
        return HostResponse::error(ErrorCode::DesktopOffline, "StarAxis桌面端连接失败");
    }
    match read_internal_frame(&mut stream)
        .and_then(|bytes| serde_json::from_slice::<HostResponse>(&bytes).map_err(io::Error::other))
    {
        Ok(response) => response,
        Err(_) => HostResponse::error(ErrorCode::DesktopOffline, "StarAxis桌面端连接失败"),
    }
}

fn read_native_frame(reader: &mut impl io::Read) -> io::Result<Option<Vec<u8>>> {
    let mut length = [0_u8; 4];
    match reader.read_exact(&mut length) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error),
    }
    let length = usize::try_from(u32::from_ne_bytes(length))
        .map_err(|_| io::Error::other("invalid native frame length"))?;
    read_bounded(reader, length).map(Some)
}

fn write_native_response(writer: &mut impl io::Write, response: &HostResponse) -> io::Result<()> {
    let bytes = serde_json::to_vec(response).map_err(io::Error::other)?;
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(io::Error::other("native response exceeds limit"));
    }
    let length = u32::try_from(bytes.len()).map_err(io::Error::other)?;
    writer.write_all(&length.to_ne_bytes())?;
    writer.write_all(&bytes)?;
    writer.flush()
}

fn read_internal_frame(reader: &mut impl io::Read) -> io::Result<Vec<u8>> {
    let mut length = [0_u8; 4];
    reader.read_exact(&mut length)?;
    let length = usize::try_from(u32::from_le_bytes(length))
        .map_err(|_| io::Error::other("invalid broker frame length"))?;
    read_bounded(reader, length)
}

fn write_internal_frame(writer: &mut impl io::Write, bytes: &[u8]) -> io::Result<()> {
    if bytes.is_empty() || bytes.len() > MAX_FRAME_BYTES {
        return Err(io::Error::other("broker frame exceeds limit"));
    }
    let length = u32::try_from(bytes.len()).map_err(io::Error::other)?;
    writer.write_all(&length.to_le_bytes())?;
    writer.write_all(bytes)?;
    writer.flush()
}

fn read_bounded(reader: &mut impl io::Read, length: usize) -> io::Result<Vec<u8>> {
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(io::Error::other("frame exceeds limit"));
    }
    let mut bytes = vec![0_u8; length];
    reader.read_exact(&mut bytes)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use vault_extension_protocol::{ErrorCode, HostResponse, MAX_FRAME_BYTES};

    use super::{caller_origin, read_native_frame, write_native_response};

    #[test]
    fn native_frames_round_trip_with_platform_length_prefix() {
        let response = HostResponse::error(ErrorCode::DesktopOffline, "offline");
        let mut bytes = Vec::new();
        write_native_response(&mut bytes, &response).expect("write frame");
        let payload = read_native_frame(&mut Cursor::new(bytes))
            .expect("read frame")
            .expect("frame exists");
        let decoded: HostResponse = serde_json::from_slice(&payload).expect("decode response");
        assert!(matches!(decoded, HostResponse::Error(_)));
    }

    #[test]
    fn oversized_native_frames_are_rejected_before_allocation() {
        let length = u32::try_from(MAX_FRAME_BYTES + 1).expect("test size");
        let error = read_native_frame(&mut Cursor::new(length.to_ne_bytes()))
            .expect_err("oversized frame must fail");
        assert_eq!(error.kind(), std::io::ErrorKind::Other);
    }

    #[test]
    fn identifies_chromium_and_firefox_callers_from_browser_arguments() {
        assert_eq!(
            caller_origin(&["chrome-extension://abc/".to_owned()]).as_deref(),
            Some("chrome-extension://abc/")
        );
        assert_eq!(
            caller_origin(&[
                "/path/to/com.staraxis.browser.json".to_owned(),
                "browser@staraxis.local".to_owned(),
            ])
            .as_deref(),
            Some("firefox-extension://browser@staraxis.local")
        );
    }
}
