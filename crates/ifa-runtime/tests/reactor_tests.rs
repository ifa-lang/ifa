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
    while !done.load(Ordering::SeqCst) && start_wait.elapsed() < Duration::from_millis(500) {
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

    // 2. Drive reactor: harvest io_uring CQE and wake the waiting coroutine
    let _ = GLOBAL_REACTOR.poll_and_wake();

    // 3. Wait for fiber to join and complete execution
    GLOBAL_SCHEDULER.join_timeout(fid, Duration::from_millis(500));

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

    // Poll reactor to process IOCP packets and wake coroutine
    let _ = GLOBAL_REACTOR.poll_and_wake();
    GLOBAL_SCHEDULER.join_timeout(fid, Duration::from_millis(500));

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
        GLOBAL_SCHEDULER.join_timeout(fid, Duration::from_millis(500));
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
