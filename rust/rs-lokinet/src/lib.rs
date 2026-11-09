use std::ffi::{CStr, CString};
use std::fmt;
use std::io;
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::os::raw::{c_char, c_int, c_void};
use std::path::{Path, PathBuf};
use std::ptr::NonNull;
use std::sync::{Arc, Mutex};
use std::time::Duration;

unsafe extern "C" {
    fn lokinet_context_new() -> *mut RawLokinet;
    fn lokinet_context_set_config(
        config: *const c_char,
        data_dir: *const c_char,
        error_buffer: *mut c_char,
        error_buffer_size: usize,
        context: *mut RawLokinet,
    ) -> c_int;
    fn lokinet_context_start(context: *mut RawLokinet) -> c_int;
    fn lokinet_context_enable_ip_packet_io(context: *mut RawLokinet) -> c_int;
    fn lokinet_ip_packet_send(
        packet: *const u8,
        packet_size: usize,
        context: *mut RawLokinet,
    ) -> c_int;
    fn lokinet_ip_packet_receive(
        packet: *mut u8,
        packet_capacity: usize,
        packet_size: *mut usize,
        timeout_ms: u32,
        context: *mut RawLokinet,
    ) -> c_int;
    fn lokinet_ip_packet_local_address(
        address: *mut c_char,
        address_capacity: usize,
        context: *mut RawLokinet,
    ) -> c_int;
    fn lokinet_ip_packet_local_ipv6_address(
        address: *mut c_char,
        address_capacity: usize,
        context: *mut RawLokinet,
    ) -> c_int;
    fn lokinet_status(context: *mut RawLokinet) -> c_int;
    fn lokinet_address(context: *mut RawLokinet) -> *mut c_char;
    fn lokinet_context_free(context: *mut RawLokinet);
    fn free(pointer: *mut c_void);
    fn lokinet_udp_bind(
        exposed_port: u16,
        filter: unsafe extern "C" fn(
            userdata: *mut c_void,
            remote: *const RawUdpFlowInfo,
            flow_userdata: *mut *mut c_void,
            timeout_seconds: *mut c_int,
        ) -> c_int,
        recv: unsafe extern "C" fn(
            remote: *const RawUdpFlowInfo,
            data: *const c_char,
            length: usize,
            flow_userdata: *mut c_void,
        ),
        timeout: unsafe extern "C" fn(remote: *const RawUdpFlowInfo, flow_userdata: *mut c_void),
        userdata: *mut c_void,
        result: *mut RawUdpBindResult,
        context: *mut RawLokinet,
    ) -> c_int;
    fn lokinet_udp_establish(
        create_flow: unsafe extern "C" fn(
            userdata: *mut c_void,
            flow_userdata: *mut *mut c_void,
            timeout_seconds: *mut c_int,
        ),
        userdata: *mut c_void,
        remote: *const RawUdpFlowInfo,
        context: *mut RawLokinet,
    ) -> c_int;
    fn lokinet_udp_flow_send(
        remote: *const RawUdpFlowInfo,
        data: *const c_void,
        length: usize,
        context: *mut RawLokinet,
    ) -> c_int;
    fn lokinet_udp_close(socket_id: c_int, context: *mut RawLokinet);
    fn lokinet_outbound_stream(
        result: *mut RawStreamResult,
        remote: *const c_char,
        local: *const c_char,
        context: *mut RawLokinet,
    );
    fn lokinet_inbound_stream_filter(
        filter: unsafe extern "C" fn(
            remote: *const c_char,
            port: u16,
            userdata: *mut c_void,
        ) -> c_int,
        userdata: *mut c_void,
        context: *mut RawLokinet,
    ) -> c_int;
    fn lokinet_close_stream(stream_id: c_int, context: *mut RawLokinet);
}

#[repr(C)]
struct RawLokinet {
    _private: [u8; 0],
}

#[repr(C)]
struct RawUdpFlowInfo {
    remote_host: [c_char; 256],
    remote_port: u16,
    socket_id: c_int,
}

#[repr(C)]
struct RawUdpBindResult {
    socket_id: c_int,
}

#[repr(C)]
struct RawStreamResult {
    error: c_int,
    local_address: [c_char; 256],
    local_port: c_int,
    stream_id: c_int,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    config_text: String,
    data_dir: PathBuf,
}

impl Config {
    pub fn new(config_text: impl Into<String>, data_dir: impl Into<PathBuf>) -> Self {
        Self {
            config_text: config_text.into(),
            data_dir: data_dir.into(),
        }
    }

    pub fn validate(self) -> Result<ValidatedConfig, Error> {
        if self.config_text.contains('\0') {
            return Err(Error::InvalidString);
        }
        if !self.data_dir.is_absolute() {
            return Err(Error::DataDirectoryMustBeAbsolute(self.data_dir));
        }
        Ok(ValidatedConfig {
            config_text: self.config_text,
            data_dir: self.data_dir,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedConfig {
    config_text: String,
    data_dir: PathBuf,
}

impl ValidatedConfig {
    pub fn config_text(&self) -> &str {
        &self.config_text
    }

    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }
}

#[derive(Debug)]
pub enum Error {
    DataDirectoryMustBeAbsolute(PathBuf),
    InvalidStreamResult,
    InvalidAddress,
    InvalidString,
    InvalidUdpFlow,
    Native(String),
    NativeCall {
        operation: &'static str,
        code: c_int,
    },
    NullHandle,
    NonUtf8Path(PathBuf),
    TimeoutOutOfRange,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DataDirectoryMustBeAbsolute(path) => {
                write!(
                    f,
                    "Lokinet data directory must be absolute: {}",
                    path.display()
                )
            }
            Self::InvalidStreamResult => write!(f, "Lokinet returned an invalid TCP stream result"),
            Self::InvalidAddress => write!(f, "Lokinet returned an invalid address"),
            Self::InvalidString => write!(f, "Lokinet config contains an interior NUL"),
            Self::InvalidUdpFlow => write!(f, "invalid Lokinet UDP flow"),
            Self::Native(message) => write!(f, "Lokinet initialization failed: {message}"),
            Self::NativeCall { operation, code } => {
                write!(f, "Lokinet {operation} failed with error {code}")
            }
            Self::NullHandle => write!(f, "Lokinet returned a null handle"),
            Self::NonUtf8Path(path) => {
                write!(
                    f,
                    "Lokinet data directory is not valid UTF-8: {}",
                    path.display()
                )
            }
            Self::TimeoutOutOfRange => write!(f, "Lokinet UDP flow timeout is out of range"),
        }
    }
}

impl std::error::Error for Error {}

struct ContextInner {
    raw: NonNull<RawLokinet>,
}

// The native context serializes public API access internally and is freed only
// after its last Rust owner and every stream/socket handle have been dropped.
unsafe impl Send for ContextInner {}
unsafe impl Sync for ContextInner {}

impl Drop for ContextInner {
    fn drop(&mut self) {
        unsafe { lokinet_context_free(self.raw.as_ptr()) };
    }
}

pub struct Runtime {
    inner: Arc<ContextInner>,
}

impl Runtime {
    pub fn start(config: Config) -> Result<Self, Error> {
        Self::start_inner(config, false)
    }

    pub fn start_with_ip_packet_io(config: Config) -> Result<(Self, IpPacketIo), Error> {
        let runtime = Self::start_inner(config, true)?;
        let packet_io = IpPacketIo {
            inner: Arc::clone(&runtime.inner),
        };
        Ok((runtime, packet_io))
    }

    fn start_inner(config: Config, enable_ip_packet_io: bool) -> Result<Self, Error> {
        let config = config.validate()?;
        let config_text = CString::new(config.config_text).map_err(|_| Error::InvalidString)?;
        let data_dir = config
            .data_dir
            .to_str()
            .ok_or_else(|| Error::NonUtf8Path(config.data_dir.clone()))?;
        let data_dir = CString::new(data_dir).map_err(|_| Error::InvalidString)?;

        let raw = NonNull::new(unsafe { lokinet_context_new() }).ok_or(Error::NullHandle)?;
        let runtime = Self {
            inner: Arc::new(ContextInner { raw }),
        };
        let mut error_buffer = [0 as c_char; 1024];
        let result = unsafe {
            lokinet_context_set_config(
                config_text.as_ptr(),
                data_dir.as_ptr(),
                error_buffer.as_mut_ptr(),
                error_buffer.len(),
                runtime.inner.raw.as_ptr(),
            )
        };
        if result != 0 {
            let message = unsafe { CStr::from_ptr(error_buffer.as_ptr()) }
                .to_string_lossy()
                .into_owned();
            return Err(Error::Native(message));
        }

        if enable_ip_packet_io {
            let result = unsafe { lokinet_context_enable_ip_packet_io(runtime.inner.raw.as_ptr()) };
            if result != 0 {
                return Err(Error::NativeCall {
                    operation: "IP packet I/O enable",
                    code: result,
                });
            }
        }

        if unsafe { lokinet_context_start(runtime.inner.raw.as_ptr()) } != 0 {
            return Err(Error::Native(
                "failed to start the Lokinet context".to_owned(),
            ));
        }
        Ok(runtime)
    }

    pub fn ip_packet_local_address(&self) -> Result<IpAddr, Error> {
        self.ip_packet_local_address_inner(false)
    }

    pub fn ip_packet_local_ipv6_address(&self) -> Result<IpAddr, Error> {
        self.ip_packet_local_address_inner(true)
    }

    fn ip_packet_local_address_inner(&self, ipv6: bool) -> Result<IpAddr, Error> {
        let mut address = [0 as c_char; 64];
        let result = unsafe {
            if ipv6 {
                lokinet_ip_packet_local_ipv6_address(
                    address.as_mut_ptr(),
                    address.len(),
                    self.inner.raw.as_ptr(),
                )
            } else {
                lokinet_ip_packet_local_address(
                    address.as_mut_ptr(),
                    address.len(),
                    self.inner.raw.as_ptr(),
                )
            }
        };
        if result != 0 {
            return Err(Error::NativeCall {
                operation: "IP packet local address",
                code: result,
            });
        }
        let address = unsafe { CStr::from_ptr(address.as_ptr()) }
            .to_str()
            .map_err(|_| Error::InvalidAddress)?;
        address.parse().map_err(|_| Error::InvalidAddress)
    }

    pub fn is_connected(&self) -> bool {
        unsafe { lokinet_status(self.inner.raw.as_ptr()) == 0 }
    }

    pub fn address(&self) -> Result<Option<String>, Error> {
        let Some(address) = NonNull::new(unsafe { lokinet_address(self.inner.raw.as_ptr()) })
        else {
            return Ok(None);
        };
        let decoded = unsafe { CStr::from_ptr(address.as_ptr()) }
            .to_str()
            .map(str::to_owned)
            .map_err(|_| Error::InvalidAddress);
        unsafe { free(address.as_ptr().cast()) };
        decoded.map(Some)
    }

    pub fn bind_udp<F, R, T>(
        &self,
        exposed_port: u16,
        filter: F,
        receive: R,
        timeout: T,
    ) -> Result<UdpSocket, Error>
    where
        F: Fn(&UdpFlow) -> Option<NonZeroU32> + Send + Sync + 'static,
        R: Fn(UdpFlow, Vec<u8>) + Send + Sync + 'static,
        T: Fn(UdpFlow) + Send + Sync + 'static,
    {
        let mut callbacks = Box::new(UdpCallbacks {
            filter: Box::new(filter),
            receive: Box::new(receive),
            timeout: Box::new(timeout),
        });
        let userdata = (&mut *callbacks as *mut UdpCallbacks).cast::<c_void>();
        let mut result = RawUdpBindResult { socket_id: 0 };
        let code = unsafe {
            lokinet_udp_bind(
                exposed_port,
                udp_filter_callback,
                udp_receive_callback,
                udp_timeout_callback,
                userdata,
                &mut result,
                self.inner.raw.as_ptr(),
            )
        };
        if code != 0 {
            return Err(Error::NativeCall {
                operation: "UDP bind",
                code,
            });
        }
        Ok(UdpSocket {
            inner: Arc::new(UdpSocketInner {
                context: Arc::clone(&self.inner),
                socket_id: result.socket_id,
                callbacks: Mutex::new(Some(callbacks)),
            }),
        })
    }

    pub fn open_tcp_stream(&self, remote: &str, local: Option<&str>) -> Result<TcpStream, Error> {
        let remote = CString::new(remote).map_err(|_| Error::InvalidString)?;
        let local = local
            .map(CString::new)
            .transpose()
            .map_err(|_| Error::InvalidString)?;
        let mut result = RawStreamResult {
            error: 0,
            local_address: [0; 256],
            local_port: 0,
            stream_id: 0,
        };
        unsafe {
            lokinet_outbound_stream(
                &mut result,
                remote.as_ptr(),
                local
                    .as_ref()
                    .map_or(std::ptr::null(), |value| value.as_ptr()),
                self.inner.raw.as_ptr(),
            )
        };
        if result.error != 0 {
            return Err(Error::NativeCall {
                operation: "outbound TCP stream",
                code: result.error,
            });
        }
        let Some(local_address) =
            decode_fixed_string(&result.local_address).filter(|address| !address.is_empty())
        else {
            unsafe { lokinet_close_stream(result.stream_id, self.inner.raw.as_ptr()) };
            return Err(Error::InvalidStreamResult);
        };
        let Some(local_port) = u16::try_from(result.local_port)
            .ok()
            .filter(|port| *port != 0)
        else {
            unsafe { lokinet_close_stream(result.stream_id, self.inner.raw.as_ptr()) };
            return Err(Error::InvalidStreamResult);
        };
        Ok(TcpStream {
            inner: Arc::new(TcpStreamInner {
                context: Arc::clone(&self.inner),
                stream_id: result.stream_id,
                local_address,
                local_port,
            }),
        })
    }

    pub fn listen_tcp_stream<F>(&self, filter: F) -> Result<TcpListener, Error>
    where
        F: Fn(&str, u16) -> StreamDecision + Send + Sync + 'static,
    {
        let mut callback = Box::new(StreamFilterData {
            filter: Box::new(filter),
        });
        let userdata = (&mut *callback as *mut StreamFilterData).cast::<c_void>();
        let stream_id = unsafe {
            lokinet_inbound_stream_filter(stream_filter_callback, userdata, self.inner.raw.as_ptr())
        };
        if stream_id < 0 {
            return Err(Error::NativeCall {
                operation: "inbound TCP listener",
                code: stream_id,
            });
        }
        Ok(TcpListener {
            inner: Arc::new(TcpListenerInner {
                context: Arc::clone(&self.inner),
                stream_id,
                callback: Mutex::new(Some(callback)),
            }),
        })
    }
}

#[derive(Clone)]
pub struct IpPacketIo {
    inner: Arc<ContextInner>,
}

impl IpPacketIo {
    pub fn receive(&self, buffer: &mut [u8], timeout: Duration) -> io::Result<usize> {
        let timeout_ms = u32::try_from(timeout.as_millis()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "packet receive timeout exceeds the native API limit",
            )
        })?;
        let mut packet_size = 0;
        let result = unsafe {
            lokinet_ip_packet_receive(
                buffer.as_mut_ptr(),
                buffer.len(),
                &mut packet_size,
                timeout_ms,
                self.inner.raw.as_ptr(),
            )
        };
        if result != 0 {
            return Err(io::Error::from_raw_os_error(result));
        }
        if packet_size > buffer.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Lokinet returned an oversized IP packet",
            ));
        }
        Ok(packet_size)
    }

    pub fn send_packet(&self, packet: &[u8]) -> io::Result<()> {
        let result = unsafe {
            lokinet_ip_packet_send(packet.as_ptr(), packet.len(), self.inner.raw.as_ptr())
        };
        if result != 0 {
            return Err(io::Error::from_raw_os_error(result));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UdpFlow {
    remote_host: String,
    remote_port: u16,
    socket_id: c_int,
}

impl UdpFlow {
    pub fn remote_host(&self) -> &str {
        &self.remote_host
    }

    pub fn remote_port(&self) -> u16 {
        self.remote_port
    }
}

struct UdpCallbacks {
    filter: Box<dyn Fn(&UdpFlow) -> Option<NonZeroU32> + Send + Sync>,
    receive: Box<dyn Fn(UdpFlow, Vec<u8>) + Send + Sync>,
    timeout: Box<dyn Fn(UdpFlow) + Send + Sync>,
}

struct UdpSocketInner {
    context: Arc<ContextInner>,
    socket_id: c_int,
    callbacks: Mutex<Option<Box<UdpCallbacks>>>,
}

impl Drop for UdpSocketInner {
    fn drop(&mut self) {
        unsafe { lokinet_udp_close(self.socket_id, self.context.raw.as_ptr()) };
        drop(
            self.callbacks
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take(),
        );
    }
}

#[derive(Clone)]
pub struct UdpSocket {
    inner: Arc<UdpSocketInner>,
}

impl UdpSocket {
    pub fn establish(
        &self,
        remote_host: &str,
        remote_port: u16,
        timeout_seconds: NonZeroU32,
    ) -> Result<UdpFlow, Error> {
        let timeout_seconds =
            c_int::try_from(timeout_seconds.get()).map_err(|_| Error::TimeoutOutOfRange)?;
        let flow = encode_udp_flow(remote_host, remote_port, self.inner.socket_id)?;
        let callbacks = self
            .inner
            .callbacks
            .lock()
            .map_err(|_| Error::Native("UDP callback storage is poisoned".to_owned()))?;
        let callback_data = callbacks
            .as_ref()
            .expect("UDP callback data remains alive until the socket is closed");
        let mut request = OutboundFlowRequest {
            callback_data: (&**callback_data as *const UdpCallbacks).cast_mut().cast(),
            timeout_seconds,
        };
        let code = unsafe {
            lokinet_udp_establish(
                udp_create_flow_callback,
                (&mut request as *mut OutboundFlowRequest).cast(),
                &flow,
                self.inner.context.raw.as_ptr(),
            )
        };
        if code != 0 {
            return Err(Error::NativeCall {
                operation: "UDP flow establishment",
                code,
            });
        }
        decode_udp_flow(&flow).ok_or(Error::InvalidUdpFlow)
    }

    pub fn send(&self, flow: &UdpFlow, data: &[u8]) -> Result<(), Error> {
        if flow.socket_id != self.inner.socket_id {
            return Err(Error::InvalidUdpFlow);
        }
        let raw_flow = encode_udp_flow(&flow.remote_host, flow.remote_port, flow.socket_id)?;
        let code = unsafe {
            lokinet_udp_flow_send(
                &raw_flow,
                data.as_ptr().cast(),
                data.len(),
                self.inner.context.raw.as_ptr(),
            )
        };
        if code != 0 {
            return Err(Error::NativeCall {
                operation: "UDP send",
                code,
            });
        }
        Ok(())
    }
}

struct OutboundFlowRequest {
    callback_data: *mut c_void,
    timeout_seconds: c_int,
}

unsafe extern "C" fn udp_create_flow_callback(
    userdata: *mut c_void,
    flow_userdata: *mut *mut c_void,
    timeout_seconds: *mut c_int,
) {
    if userdata.is_null() || flow_userdata.is_null() || timeout_seconds.is_null() {
        return;
    }
    let request = unsafe { &*userdata.cast::<OutboundFlowRequest>() };
    unsafe {
        *flow_userdata = request.callback_data;
        *timeout_seconds = request.timeout_seconds;
    }
}

unsafe extern "C" fn udp_filter_callback(
    userdata: *mut c_void,
    remote: *const RawUdpFlowInfo,
    flow_userdata: *mut *mut c_void,
    timeout_seconds: *mut c_int,
) -> c_int {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if userdata.is_null() || flow_userdata.is_null() || timeout_seconds.is_null() {
            return 1;
        }
        let Some(flow) = (unsafe { remote.as_ref() }).and_then(decode_udp_flow) else {
            return 1;
        };
        let callbacks = unsafe { &*userdata.cast::<UdpCallbacks>() };
        match (callbacks.filter)(&flow) {
            Some(timeout) => {
                let Ok(seconds) = c_int::try_from(timeout.get()) else {
                    return 1;
                };
                unsafe {
                    *flow_userdata = userdata;
                    *timeout_seconds = seconds;
                }
                0
            }
            None => 1,
        }
    }))
    .unwrap_or(1)
}

unsafe extern "C" fn udp_receive_callback(
    remote: *const RawUdpFlowInfo,
    data: *const c_char,
    length: usize,
    flow_userdata: *mut c_void,
) {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if flow_userdata.is_null()
            || (data.is_null() && length != 0)
            || length > isize::MAX as usize
        {
            return;
        }
        let Some(flow) = (unsafe { remote.as_ref() }).and_then(decode_udp_flow) else {
            return;
        };
        let packet = if length == 0 {
            Vec::new()
        } else {
            unsafe { std::slice::from_raw_parts(data.cast::<u8>(), length) }.to_vec()
        };
        let callbacks = unsafe { &*flow_userdata.cast::<UdpCallbacks>() };
        (callbacks.receive)(flow, packet)
    }));
}

unsafe extern "C" fn udp_timeout_callback(
    remote: *const RawUdpFlowInfo,
    flow_userdata: *mut c_void,
) {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if flow_userdata.is_null() {
            return;
        }
        let Some(flow) = (unsafe { remote.as_ref() }).and_then(decode_udp_flow) else {
            return;
        };
        let callbacks = unsafe { &*flow_userdata.cast::<UdpCallbacks>() };
        (callbacks.timeout)(flow)
    }));
}

fn encode_udp_flow(
    remote_host: &str,
    remote_port: u16,
    socket_id: c_int,
) -> Result<RawUdpFlowInfo, Error> {
    if remote_host.is_empty()
        || remote_host.as_bytes().len() >= 256
        || remote_host.contains('\0')
        || remote_port == 0
    {
        return Err(Error::InvalidUdpFlow);
    }
    let mut host = [0; 256];
    for (target, source) in host.iter_mut().zip(remote_host.bytes()) {
        *target = source as c_char;
    }
    Ok(RawUdpFlowInfo {
        remote_host: host,
        remote_port,
        socket_id,
    })
}

fn decode_udp_flow(raw: &RawUdpFlowInfo) -> Option<UdpFlow> {
    let host = decode_fixed_string(&raw.remote_host)?;
    if host.is_empty() || raw.remote_port == 0 {
        return None;
    }
    Some(UdpFlow {
        remote_host: host,
        remote_port: raw.remote_port,
        socket_id: raw.socket_id,
    })
}

fn decode_fixed_string(raw: &[c_char]) -> Option<String> {
    let bytes = raw
        .iter()
        .map(|byte| *byte as u8)
        .take_while(|byte| *byte != 0)
        .collect::<Vec<_>>();
    String::from_utf8(bytes).ok()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamDecision {
    Accept,
    Reject,
    Drop,
}

type StreamFilter = dyn Fn(&str, u16) -> StreamDecision + Send + Sync;

struct StreamFilterData {
    filter: Box<StreamFilter>,
}

struct TcpStreamInner {
    context: Arc<ContextInner>,
    stream_id: c_int,
    local_address: String,
    local_port: u16,
}

impl Drop for TcpStreamInner {
    fn drop(&mut self) {
        unsafe { lokinet_close_stream(self.stream_id, self.context.raw.as_ptr()) };
    }
}

#[derive(Clone)]
pub struct TcpStream {
    inner: Arc<TcpStreamInner>,
}

impl TcpStream {
    pub fn local_address(&self) -> &str {
        &self.inner.local_address
    }

    pub fn local_port(&self) -> u16 {
        self.inner.local_port
    }

    pub fn stream_id(&self) -> c_int {
        self.inner.stream_id
    }
}

struct TcpListenerInner {
    context: Arc<ContextInner>,
    stream_id: c_int,
    callback: Mutex<Option<Box<StreamFilterData>>>,
}

impl Drop for TcpListenerInner {
    fn drop(&mut self) {
        unsafe { lokinet_close_stream(self.stream_id, self.context.raw.as_ptr()) };
        self.callback
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
    }
}

#[derive(Clone)]
pub struct TcpListener {
    inner: Arc<TcpListenerInner>,
}

impl TcpListener {
    pub fn stream_id(&self) -> c_int {
        self.inner.stream_id
    }
}

unsafe extern "C" fn stream_filter_callback(
    remote: *const c_char,
    port: u16,
    userdata: *mut c_void,
) -> c_int {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if remote.is_null() || userdata.is_null() {
            return -1;
        }
        let Ok(remote) = (unsafe { CStr::from_ptr(remote) }).to_str() else {
            return -1;
        };
        let filter = unsafe { &*userdata.cast::<StreamFilterData>() };
        match (filter.filter)(remote, port) {
            StreamDecision::Accept => 0,
            StreamDecision::Reject => -1,
            StreamDecision::Drop => -2,
        }
    }))
    .unwrap_or(-1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn runtime_and_handles_are_send_and_sync() {
        assert_send_sync::<Runtime>();
        assert_send_sync::<UdpSocket>();
        assert_send_sync::<TcpStream>();
        assert_send_sync::<TcpListener>();
    }

    #[test]
    fn rejects_relative_state_directory() {
        let err = Config::new("", "relative-state").validate().unwrap_err();
        assert!(matches!(err, Error::DataDirectoryMustBeAbsolute(_)));
    }

    #[test]
    fn accepts_explicit_absolute_state_directory() {
        let config = Config::new("", "/state/lokinet").validate().unwrap();
        assert_eq!(config.data_dir(), Path::new("/state/lokinet"));
    }

    #[test]
    fn udp_flow_requires_a_valid_host_and_port() {
        assert!(encode_udp_flow("remote.loki", 1234, 1).is_ok());
        assert!(encode_udp_flow("", 1234, 1).is_err());
        assert!(encode_udp_flow("remote.loki", 0, 1).is_err());
        assert!(encode_udp_flow(&"x".repeat(256), 1234, 1).is_err());
    }

    #[test]
    fn udp_flow_round_trips_through_the_c_layout() {
        let raw = encode_udp_flow("remote.loki", 1234, 7).unwrap();
        let flow = decode_udp_flow(&raw).unwrap();
        assert_eq!(flow.remote_host(), "remote.loki");
        assert_eq!(flow.remote_port(), 1234);
        assert_eq!(flow.socket_id, 7);
    }
}
