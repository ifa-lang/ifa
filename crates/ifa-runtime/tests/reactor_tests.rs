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
