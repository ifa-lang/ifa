use ifa_runtime::reactor::io_uring::opcodes;
use ifa_runtime::reactor::{
    AsyncTcpListener, AsyncTcpStream, AsyncTimer, IoUringConnector, IoUringSqe, IocpConnector,
};
use ifa_runtime::{ifa_rt_async_sleep, ifa_rt_async_tcp_listen, GLOBAL_REACTOR, GLOBAL_SCHEDULER};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[test]
fn test_io_uring_connector_submission_and_completion() {
    let connector = IoUringConnector::new(32);
    let sqe = IoUringSqe {
        opcode: opcodes::IORING_OP_NOP,
        user_data: 0xABCD,
        ..Default::default()
    };

    connector.submit_sqe(sqe);
    let entered = connector.enter(1);
    assert!(entered >= 1 || connector.is_available());

    let cqe = connector.pop_cqe();
    if let Some(cqe) = cqe {
        assert_eq!(cqe.user_data, 0xABCD);
    }
}

#[test]
fn test_iocp_connector_post_and_poll() {
    let connector = IocpConnector::new(1);
    let posted = connector.post_completion(42, 1024, 0x1234, 0);
    assert!(posted);

    let packet = connector.poll_completion(10);
    assert!(packet.is_some());
    let p = packet.unwrap();
    assert_eq!(p.key, 42);
    assert_eq!(p.bytes_transferred, 1024);
}

#[test]
fn test_async_timer_sleep_cooperative() {
    let start = Instant::now();
    AsyncTimer::sleep(Duration::from_millis(30));
    assert!(start.elapsed() >= Duration::from_millis(25));
}

#[test]
fn test_async_tcp_listener_and_stream_fiber_echo() {
    // Bind async listener to random ephemeral port
    let listener = AsyncTcpListener::bind("127.0.0.1:0").expect("Failed to bind async listener");
    let addr = listener.local_addr().unwrap();

    let done = Arc::new(AtomicBool::new(false));
    let done_server = Arc::clone(&done);

    // Spawn server fiber
    GLOBAL_SCHEDULER.spawn(move || {
        let (mut stream, _) = listener.accept().expect("Accept failed");
        let mut buf = [0u8; 12];
        let n = stream.read(&mut buf).expect("Read failed");
        assert_eq!(&buf[..n], b"hello-ifa-io");
        stream.write_all(b"pong-ifa").expect("Write failed");
        done_server.store(true, Ordering::SeqCst);
    });

    // Client fiber
    let mut client = AsyncTcpStream::connect(addr).expect("Connect failed");
    client.write_all(b"hello-ifa-io").expect("Client write");

    let mut reply = [0u8; 8];
    let n = client.read(&mut reply).expect("Client read");
    assert_eq!(&reply[..n], b"pong-ifa");

    let start_wait = Instant::now();
    while !done.load(Ordering::SeqCst) && start_wait.elapsed() < Duration::from_secs(15) {
        std::thread::yield_now();
    }
    assert!(done.load(Ordering::SeqCst));
}

#[test]
fn test_global_reactor_ffi_calls() {
    ifa_rt_async_sleep(10);

    let listen_id = ifa_rt_async_tcp_listen(0, 128);
    assert!(listen_id >= 1000);
    assert!(GLOBAL_REACTOR.close(listen_id));
}

#[repr(C)]
struct CoroIoTestFrame {
    stage: i32,
    result_slot: i64,
    buf: [u8; 32],
    coro_ptr: *mut ifa_runtime::ffi::IfaCoroutine,
    fd_read: i32,
    success: bool,
}

extern "C" fn coro_io_uring_test_resume(frame_ptr: *mut u8) -> i32 {
    let frame = unsafe { &mut *(frame_ptr as *mut CoroIoTestFrame) };
    match frame.stage {
        0 => {
            frame.stage = 1;
            let _token = ifa_runtime::ffi::ifa_rt_coro_register_io_uring_read(
                frame.coro_ptr,
                frame.fd_read,
                frame.buf.as_mut_ptr(),
                15,
                0,
                &mut frame.result_slot,
            );
            // Coroutine suspends waiting for io_uring completion
            ifa_runtime::CoroStatus::WaitingIo as i32
        }
        1 => {
            frame.stage = 2;
            assert_eq!(frame.result_slot, 15);
            assert_eq!(&frame.buf[..15], b"ifa_coro_io_ok!");
            frame.success = true;
            ifa_runtime::CoroStatus::Completed as i32
        }
        _ => ifa_runtime::CoroStatus::Completed as i32,
    }
}

#[test]
fn test_coroutine_io_uring_integration_and_scheduler_wake() {
    let mut pipe_fds = [0i32; 2];
    #[cfg(unix)]
    unsafe {
        assert_eq!(libc::pipe(pipe_fds.as_mut_ptr()), 0);
        let msg = b"ifa_coro_io_ok!";
        assert_eq!(
            libc::write(pipe_fds[1], msg.as_ptr() as *const libc::c_void, msg.len()),
            msg.len() as isize
        );
    }

    let frame = Box::into_raw(Box::new(CoroIoTestFrame {
        stage: 0,
        result_slot: -1,
        buf: [0u8; 32],
        coro_ptr: std::ptr::null_mut(),
        fd_read: pipe_fds[0],
        success: false,
    }));

    let coro = ifa_runtime::ffi::ifa_rt_coro_create_custom(
        frame as *mut u8,
        coro_io_uring_test_resume,
        None,
    );
    unsafe {
        (*frame).coro_ptr = coro;
    }

    // 1. Spawn coroutine directly into global M:N scheduler
    let fid = ifa_runtime::ffi::ifa_rt_coro_spawn(coro);
    assert!(fid > 0);

    // 2. Drive reactor and wait for completion in bounded loop
    let mut completed = false;
    let deadline = Instant::now() + Duration::from_secs(15);
    while !completed && Instant::now() < deadline {
        GLOBAL_REACTOR.poll_and_wake();
        completed = GLOBAL_SCHEDULER.join_timeout(fid, Duration::from_millis(50));
    }

    assert!(
        completed,
        "Fiber timed out waiting for io_uring completion in M:N reactor test"
    );

    unsafe {
        assert!((*frame).success);
        assert_eq!((*frame).result_slot, 15);
        let _ = Box::from_raw(frame);
    }
    ifa_runtime::ffi::ifa_rt_coro_destroy(coro);

    #[cfg(unix)]
    unsafe {
        libc::close(pipe_fds[0]);
        libc::close(pipe_fds[1]);
    }
}

#[repr(C)]
struct CoroIocpTestFrame {
    stage: i32,
    result_slot: i64,
    buf: [u8; 16],
    coro_ptr: *mut ifa_runtime::ffi::IfaCoroutine,
    success: bool,
}

extern "C" fn coro_iocp_test_resume(frame_ptr: *mut u8) -> i32 {
    let frame = unsafe { &mut *(frame_ptr as *mut CoroIocpTestFrame) };
    match frame.stage {
        0 => {
            frame.stage = 1;
            let _token = ifa_runtime::ffi::ifa_rt_coro_register_iocp_write(
                frame.coro_ptr,
                100,
                frame.buf.as_ptr(),
                16,
                &mut frame.result_slot,
            );
            ifa_runtime::CoroStatus::WaitingIo as i32
        }
        1 => {
            frame.stage = 2;
            assert_eq!(frame.result_slot, 16);
            frame.success = true;
            ifa_runtime::CoroStatus::Completed as i32
        }
        _ => ifa_runtime::CoroStatus::Completed as i32,
    }
}

#[test]
fn test_coroutine_iocp_integration_and_scheduler_wake() {
    let frame = Box::into_raw(Box::new(CoroIocpTestFrame {
        stage: 0,
        result_slot: -1,
        buf: *b"1234567890abcdef",
        coro_ptr: std::ptr::null_mut(),
        success: false,
    }));

    let coro =
        ifa_runtime::ffi::ifa_rt_coro_create_custom(frame as *mut u8, coro_iocp_test_resume, None);
    unsafe {
        (*frame).coro_ptr = coro;
    }

    let fid = ifa_runtime::ffi::ifa_rt_coro_spawn(coro);
    assert!(fid > 0);

    // Poll reactor and wait for completion in bounded loop
    let mut completed = false;
    let deadline = Instant::now() + Duration::from_secs(15);
    while !completed && Instant::now() < deadline {
        GLOBAL_REACTOR.poll_and_wake();
        completed = GLOBAL_SCHEDULER.join_timeout(fid, Duration::from_millis(50));
    }
    assert!(
        completed,
        "Fiber timed out waiting for IOCP completion in M:N reactor test"
    );

    unsafe {
        assert!((*frame).success);
        assert_eq!((*frame).result_slot, 16);
        let _ = Box::from_raw(frame);
    }
    ifa_runtime::ffi::ifa_rt_coro_destroy(coro);
}

#[test]
fn test_concurrent_coroutines_mn_reactor_io() {
    let mut fids = Vec::new();
    let mut frames = Vec::new();

    for i in 0..10 {
        let frame = Box::into_raw(Box::new(CoroIocpTestFrame {
            stage: 0,
            result_slot: -1,
            buf: [i as u8; 16],
            coro_ptr: std::ptr::null_mut(),
            success: false,
        }));
        let coro = ifa_runtime::ffi::ifa_rt_coro_create_custom(
            frame as *mut u8,
            coro_iocp_test_resume,
            None,
        );
        unsafe {
            (*frame).coro_ptr = coro;
        }
        let fid = ifa_runtime::ffi::ifa_rt_coro_spawn(coro);
        fids.push((fid, coro));
        frames.push(frame);
    }

    // Process all completions concurrently
    GLOBAL_REACTOR.poll_and_wake();
    for (fid, coro) in fids {
        let mut completed = false;
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        while !completed && std::time::Instant::now() < deadline {
            GLOBAL_REACTOR.poll_and_wake();
            completed = GLOBAL_SCHEDULER.join_timeout(fid, Duration::from_millis(50));
        }
        assert!(
            completed,
            "Fiber timed out waiting for completion in M:N reactor test"
        );
        ifa_runtime::ffi::ifa_rt_coro_destroy(coro);
    }

    for frame in frames {
        unsafe {
            assert!((*frame).success);
            assert_eq!((*frame).result_slot, 16);
            let _ = Box::from_raw(frame);
        }
    }
}

#[test]
fn test_io_uring_timeout_and_cancellation() {
    let connector = IoUringConnector::new(32);
    // 1. Submit a timeout of 50ms
    let sqe = IoUringSqe {
        opcode: opcodes::IORING_OP_TIMEOUT,
        off: 50_000_000, // 50ms in nanos
        user_data: 0x9001,
        ..Default::default()
    };
    connector.submit_sqe(sqe);
    let entered = connector.enter(0);
    assert_eq!(entered, 0); // Not completed yet
    assert_eq!(connector.active_timeouts_count(), 1);

    // Immediate check before time elapses: no CQE
    assert!(connector.pop_cqe().is_none());

    // 2. Submit cancellation
    let cancel_sqe = IoUringSqe {
        opcode: opcodes::IORING_OP_TIMEOUT_REMOVE,
        addr: 0x9001,
        user_data: 0x9002,
        ..Default::default()
    };
    connector.submit_sqe(cancel_sqe);
    connector.enter(0);

    // Cancel CQE should succeed with res = 0
    let cqe = connector.pop_cqe().expect("Expected cancellation CQE");
    assert_eq!(cqe.user_data, 0x9002);
    assert_eq!(cqe.res, 0);
    assert_eq!(connector.active_timeouts_count(), 0);

    // 3. Submit a short timeout (15ms) and wait for expiration
    let sqe2 = IoUringSqe {
        opcode: opcodes::IORING_OP_TIMEOUT,
        off: 15_000_000,
        user_data: 0x9003,
        ..Default::default()
    };
    connector.submit_sqe(sqe2);
    connector.enter(0);
    assert_eq!(connector.active_timeouts_count(), 1);

    std::thread::sleep(Duration::from_millis(25));
    connector.enter(0);
    let cqe2 = connector.pop_cqe().expect("Expected expired timeout CQE");
    assert_eq!(cqe2.user_data, 0x9003);
    assert_eq!(cqe2.res, 0);
    assert_eq!(connector.active_timeouts_count(), 0);
}

#[repr(C)]
struct CoroTimeoutTestFrame {
    stage: i32,
    result_slot: i64,
    token: u64,
    coro_ptr: *mut ifa_runtime::ffi::IfaCoroutine,
    success: bool,
}

extern "C" fn coro_io_uring_timeout_resume(frame_ptr: *mut u8) -> i32 {
    let frame = unsafe { &mut *(frame_ptr as *mut CoroTimeoutTestFrame) };
    match frame.stage {
        0 => {
            frame.stage = 1;
            let token = ifa_runtime::ffi::ifa_rt_coro_register_io_uring_timeout(
                frame.coro_ptr,
                20_000_000, // 20ms
                &mut frame.result_slot,
            );
            frame.token = token;
            ifa_runtime::CoroStatus::WaitingIo as i32
        }
        1 => {
            frame.stage = 2;
            assert_eq!(frame.result_slot, 0);
            frame.success = true;
            ifa_runtime::CoroStatus::Completed as i32
        }
        _ => ifa_runtime::CoroStatus::Completed as i32,
    }
}

#[test]
fn test_coroutine_io_uring_timeout_and_scheduler_wake() {
    let frame = Box::into_raw(Box::new(CoroTimeoutTestFrame {
        stage: 0,
        result_slot: -1,
        token: 0,
        coro_ptr: std::ptr::null_mut(),
        success: false,
    }));

    let coro = ifa_runtime::ffi::ifa_rt_coro_create_custom(
        frame as *mut u8,
        coro_io_uring_timeout_resume,
        None,
    );
    unsafe {
        (*frame).coro_ptr = coro;
    }

    let fid = ifa_runtime::ffi::ifa_rt_coro_spawn(coro);
    assert!(fid > 0);

    let start = Instant::now();
    let mut completed = false;
    let deadline = Instant::now() + Duration::from_secs(10);
    while !completed && Instant::now() < deadline {
        GLOBAL_REACTOR.poll_and_wake();
        completed = GLOBAL_SCHEDULER.join_timeout(fid, Duration::from_millis(5));
    }

    assert!(
        completed,
        "Coroutine timed out waiting for io_uring timer wake"
    );
    assert!(start.elapsed() >= Duration::from_millis(15));
    unsafe {
        assert!((*frame).success);
        assert_eq!((*frame).result_slot, 0);
        let _ = Box::from_raw(frame);
    }
    ifa_runtime::ffi::ifa_rt_coro_destroy(coro);
}

#[test]
fn test_unified_select_wait_table_channels_and_io_uring_timeout() {
    let chan1 = ifa_runtime::ffi::ifa_rt_channel_create(4);
    let chan2 = ifa_runtime::ffi::ifa_rt_channel_create(4);

    let mut entries = [
        ifa_runtime::ffi::IfaSelectWaitEntry {
            chan: chan1,
            op: ifa_runtime::ffi::IFA_SELECT_OP_RECV,
            status: ifa_runtime::ffi::IFA_SELECT_STATUS_PENDING,
            val: std::ptr::null_mut(),
            priority: 10,
            _pad: 0,
            timeout_ns: 0,
        },
        ifa_runtime::ffi::IfaSelectWaitEntry {
            chan: chan2,
            op: ifa_runtime::ffi::IFA_SELECT_OP_RECV,
            status: ifa_runtime::ffi::IFA_SELECT_STATUS_PENDING,
            val: std::ptr::null_mut(),
            priority: 20,
            _pad: 0,
            timeout_ns: 0,
        },
        ifa_runtime::ffi::IfaSelectWaitEntry {
            chan: std::ptr::null_mut(),
            op: ifa_runtime::ffi::IFA_SELECT_OP_TIMEOUT,
            status: ifa_runtime::ffi::IFA_SELECT_STATUS_PENDING,
            val: std::ptr::null_mut(),
            priority: i32::MIN,
            _pad: 0,
            timeout_ns: 25_000_000, // 25ms
        },
    ];

    let mut table = ifa_runtime::ffi::IfaSelectWaitTable {
        entries: entries.as_mut_ptr(),
        count: 3,
        has_default: 0,
        _pad: 0,
        start_ns: -1,
    };

    let start = Instant::now();
    let winner = ifa_runtime::ffi::ifa_rt_channel_select_wait_table(&mut table);
    assert_eq!(
        winner, 2,
        "Timeout branch should be chosen when channels are empty"
    );
    assert!(start.elapsed() >= Duration::from_millis(20));

    ifa_runtime::ffi::ifa_rt_channel_destroy(chan1);
    ifa_runtime::ffi::ifa_rt_channel_destroy(chan2);
}

#[test]
fn test_unified_select_wait_table_channel_beats_timeout_with_cancellation() {
    let chan1 = ifa_runtime::ffi::ifa_rt_channel_create(4);
    let chan2 = ifa_runtime::ffi::ifa_rt_channel_create(4);

    let mut entries = [
        ifa_runtime::ffi::IfaSelectWaitEntry {
            chan: chan1,
            op: ifa_runtime::ffi::IFA_SELECT_OP_RECV,
            status: ifa_runtime::ffi::IFA_SELECT_STATUS_PENDING,
            val: std::ptr::null_mut(),
            priority: 10,
            _pad: 0,
            timeout_ns: 0,
        },
        ifa_runtime::ffi::IfaSelectWaitEntry {
            chan: chan2,
            op: ifa_runtime::ffi::IFA_SELECT_OP_RECV,
            status: ifa_runtime::ffi::IFA_SELECT_STATUS_PENDING,
            val: std::ptr::null_mut(),
            priority: 20,
            _pad: 0,
            timeout_ns: 0,
        },
        ifa_runtime::ffi::IfaSelectWaitEntry {
            chan: std::ptr::null_mut(),
            op: ifa_runtime::ffi::IFA_SELECT_OP_TIMEOUT,
            status: ifa_runtime::ffi::IFA_SELECT_STATUS_PENDING,
            val: std::ptr::null_mut(),
            priority: i32::MIN,
            _pad: 0,
            timeout_ns: 500_000_000, // 500ms
        },
    ];

    let mut table = ifa_runtime::ffi::IfaSelectWaitTable {
        entries: entries.as_mut_ptr(),
        count: 3,
        has_default: 0,
        _pad: 0,
        start_ns: -1,
    };

    // Producer sends on chan2 after 10ms
    let c2 = chan2 as usize;
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(10));
        let ptr = c2 as *mut ifa_runtime::ffi::IfaChannelHandle;
        let mut msg: u64 = 42;
        ifa_runtime::ffi::ifa_rt_channel_send(ptr, &mut msg as *mut u64 as *mut u8);
    });

    let start = Instant::now();
    let winner = ifa_runtime::ffi::ifa_rt_channel_select_wait_table(&mut table);
    assert_eq!(
        winner, 1,
        "Channel 2 should win as priority 20 and active before timeout"
    );
    assert!(
        start.elapsed() < Duration::from_millis(350),
        "Should complete well before the 500ms timeout"
    );

    ifa_runtime::ffi::ifa_rt_channel_destroy(chan1);
    ifa_runtime::ffi::ifa_rt_channel_destroy(chan2);
}

#[test]
fn test_unified_select_wait_table_fd_read_and_io_token() {
    let mut pipe_fds = [0i32; 2];
    #[cfg(unix)]
    unsafe {
        assert_eq!(libc::pipe(pipe_fds.as_mut_ptr()), 0);
        let msg = b"x";
        assert_eq!(
            libc::write(pipe_fds[1], msg.as_ptr() as *const libc::c_void, 1),
            1
        );
    }

    let token = GLOBAL_REACTOR.next_token();
    // Simulate an IO completion registered in the scheduler
    GLOBAL_SCHEDULER.wake_io(token, 1024);

    let mut result_slot: i64 = 0;
    let mut entries = [
        ifa_runtime::ffi::IfaSelectWaitEntry {
            chan: std::ptr::null_mut(),
            op: ifa_runtime::ffi::IFA_SELECT_OP_FD_READ,
            status: ifa_runtime::ffi::IFA_SELECT_STATUS_PENDING,
            val: std::ptr::null_mut(),
            priority: 10,
            _pad: 0,
            timeout_ns: pipe_fds[0] as u64,
        },
        ifa_runtime::ffi::IfaSelectWaitEntry {
            chan: std::ptr::null_mut(),
            op: ifa_runtime::ffi::IFA_SELECT_OP_IO_TOKEN,
            status: ifa_runtime::ffi::IFA_SELECT_STATUS_PENDING,
            val: &mut result_slot as *mut i64 as *mut u8,
            priority: 50, // higher priority!
            _pad: 0,
            timeout_ns: token,
        },
    ];

    let mut table = ifa_runtime::ffi::IfaSelectWaitTable {
        entries: entries.as_mut_ptr(),
        count: 2,
        has_default: 0,
        _pad: 0,
        start_ns: -1,
    };

    let winner = ifa_runtime::ffi::ifa_rt_channel_select_table(&mut table);
    assert_eq!(winner, 1, "IO token branch with priority 50 should win");
    assert_eq!(result_slot, 1024);

    #[cfg(unix)]
    unsafe {
        libc::close(pipe_fds[0]);
        libc::close(pipe_fds[1]);
    }
}

#[test]
fn test_async_udp_socket_echo_and_reactor_ffi() {
    use ifa_runtime::reactor::AsyncUdpSocket;
    use ifa_runtime::{
        ifa_rt_async_close, ifa_rt_async_udp_bind, ifa_rt_async_udp_port,
        ifa_rt_async_udp_recv_from, ifa_rt_async_udp_send_to,
    };

    // 1. Rust native AsyncUdpSocket layer
    let server_sock = AsyncUdpSocket::bind("127.0.0.1:0").expect("bind server udp");
    let server_addr = server_sock.local_addr().expect("local addr");
    let client_sock = AsyncUdpSocket::bind("127.0.0.1:0").expect("bind client udp");

    let sent = client_sock
        .send_to(b"IFA_UDP_DATAGRAM", server_addr)
        .expect("send_to");
    assert_eq!(sent, 16);

    let mut recv_buf = [0u8; 32];
    let (received, sender) = server_sock.recv_from(&mut recv_buf).expect("recv_from");
    assert_eq!(received, 16);
    assert_eq!(&recv_buf[..received], b"IFA_UDP_DATAGRAM");

    // Reply back
    let replied = server_sock
        .send_to(b"IFA_UDP_REPLY", sender)
        .expect("server reply");
    assert_eq!(replied, 13);

    let mut reply_buf = [0u8; 32];
    let (n_reply, _) = client_sock.recv_from(&mut reply_buf).expect("client recv");
    assert_eq!(n_reply, 13);
    assert_eq!(&reply_buf[..n_reply], b"IFA_UDP_REPLY");

    // 2. C-ABI FFI Async Reactor layer
    let s_id = ifa_rt_async_udp_bind(0);
    assert!(s_id >= 1000);
    let s_port = ifa_rt_async_udp_port(s_id);
    assert!(s_port > 0);

    let c_id = ifa_rt_async_udp_bind(0);
    assert!(c_id >= 1000);

    let host_cstr = std::ffi::CString::new("127.0.0.1").unwrap();
    let msg = b"FFI_UDP_PAYLOAD";
    let sent_ffi = ifa_rt_async_udp_send_to(
        c_id,
        host_cstr.as_ptr() as *const u8,
        s_port as u16,
        msg.as_ptr(),
        msg.len(),
    );
    assert_eq!(sent_ffi, msg.len() as isize);

    let mut ffi_recv_buf = [0u8; 64];
    let n_ffi = ifa_rt_async_udp_recv_from(s_id, ffi_recv_buf.as_mut_ptr(), ffi_recv_buf.len());
    assert_eq!(n_ffi, msg.len() as isize);
    assert_eq!(&ffi_recv_buf[..n_ffi as usize], msg);

    assert_eq!(ifa_rt_async_close(s_id), 0);
    assert_eq!(ifa_rt_async_close(c_id), 0);
}

#[test]
fn test_async_socket_options_and_udp_connected_mode() {
    use ifa_runtime::reactor::{AsyncTcpListener, AsyncTcpStream, AsyncUdpSocket};

    // 1. TCP socket options
    let listener = AsyncTcpListener::bind("127.0.0.1:0").expect("bind tcp listener");
    let l_addr = listener.local_addr().expect("tcp listener addr");
    listener.set_ttl(42).expect("set_ttl listener");
    assert_eq!(listener.ttl().expect("ttl listener"), 42);

    let client_tcp = AsyncTcpStream::connect(l_addr).expect("connect tcp client");
    let (server_tcp, _) = listener.accept().expect("accept tcp server");

    client_tcp
        .set_nodelay(true)
        .expect("client set_nodelay true");
    assert!(client_tcp.nodelay().expect("client nodelay"));
    client_tcp
        .set_nodelay(false)
        .expect("client set_nodelay false");
    assert!(!client_tcp.nodelay().expect("client nodelay"));

    server_tcp.set_ttl(55).expect("server set_ttl");
    assert_eq!(server_tcp.ttl().expect("server ttl"), 55);

    // 2. UDP socket options and connected mode
    let s_udp = AsyncUdpSocket::bind("127.0.0.1:0").expect("bind udp server");
    let c_udp = AsyncUdpSocket::bind("127.0.0.1:0").expect("bind udp client");
    let s_addr = s_udp.local_addr().expect("s_udp addr");
    let c_addr = c_udp.local_addr().expect("c_udp addr");

    s_udp.set_ttl(64).expect("s_udp set_ttl");
    assert_eq!(s_udp.ttl().expect("s_udp ttl"), 64);

    s_udp.set_broadcast(true).expect("set_broadcast");
    assert!(s_udp.broadcast().expect("broadcast"));
    s_udp.set_broadcast(false).expect("unset_broadcast");
    assert!(!s_udp.broadcast().expect("broadcast"));

    // Mode UDP connecté
    c_udp.connect(s_addr).expect("c_udp connect");
    assert_eq!(c_udp.peer_addr().expect("c_udp peer_addr"), s_addr);

    s_udp.connect(c_addr).expect("s_udp connect");
    assert_eq!(s_udp.peer_addr().expect("s_udp peer_addr"), c_addr);

    // Envoi et réception connectés
    let sent = c_udp.send(b"HELLO_CONNECTED_UDP").expect("c_udp send");
    assert_eq!(sent, 19);

    let mut buf = [0u8; 32];
    let recvd = s_udp.recv(&mut buf).expect("s_udp recv");
    assert_eq!(recvd, 19);
    assert_eq!(&buf[..recvd], b"HELLO_CONNECTED_UDP");

    // try_send et try_recv
    let try_sent = s_udp
        .try_send(b"REPLY_CONNECTED_UDP")
        .expect("s_udp try_send");
    assert_eq!(try_sent, Some(19));

    // La donnée est immédiatement prête en socket buffer local
    let mut reply_buf = [0u8; 32];
    let try_recvd = c_udp.recv(&mut reply_buf).expect("c_udp recv");
    assert_eq!(try_recvd, 19);
    assert_eq!(&reply_buf[..try_recvd], b"REPLY_CONNECTED_UDP");

    // try_recv sans données en attente doit retourner Ok(None)
    let empty_opt = c_udp
        .try_recv(&mut reply_buf)
        .expect("c_udp try_recv empty");
    assert_eq!(empty_opt, None);
}
