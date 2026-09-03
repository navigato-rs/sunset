//! An in-memory duplex pipe, and a poll loop to drive the two ends.

#![allow(dead_code)]

use core::future::{Future, poll_fn};
use core::task::{Context, Poll, Waker};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

use sunset_sftp::embedded_io_async::{ErrorType, Read, Write};
use sunset_sftp::sunset;

#[derive(Default)]
struct Inner {
    buf: VecDeque<u8>,
    closed: bool,
}

/// One direction of a connection.
#[derive(Clone, Default)]
pub struct Pipe(Rc<RefCell<Inner>>);

impl Pipe {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn reader(&self) -> PipeReader {
        PipeReader(self.0.clone())
    }

    pub fn writer(&self) -> PipeWriter {
        PipeWriter(self.0.clone())
    }

    /// Adds data for a reader to consume, used for canned responses.
    pub fn push(&self, data: &[u8]) {
        self.0.borrow_mut().buf.extend(data);
    }

    /// Makes further reads return end of file.
    pub fn close(&self) {
        self.0.borrow_mut().closed = true;
    }

    /// Takes everything that has been written.
    pub fn take(&self) -> Vec<u8> {
        self.0.borrow_mut().buf.drain(..).collect()
    }
}

pub struct PipeReader(Rc<RefCell<Inner>>);
pub struct PipeWriter(Rc<RefCell<Inner>>);

impl ErrorType for PipeReader {
    type Error = sunset::Error;
}

impl ErrorType for PipeWriter {
    type Error = sunset::Error;
}

impl Read for PipeReader {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, sunset::Error> {
        poll_fn(|_cx| {
            let mut inner = self.0.borrow_mut();
            if inner.buf.is_empty() {
                if inner.closed {
                    return Poll::Ready(Ok(0));
                }
                // run_test() polls in a loop, so no waker is needed.
                return Poll::Pending;
            }
            let l = buf.len().min(inner.buf.len());
            for b in buf.iter_mut().take(l) {
                *b = inner.buf.pop_front().unwrap();
            }
            Poll::Ready(Ok(l))
        })
        .await
    }
}

impl Write for PipeWriter {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, sunset::Error> {
        if buf.is_empty() {
            return Ok(0);
        }
        self.0.borrow_mut().buf.extend(buf);
        Ok(buf.len())
    }

    async fn flush(&mut self) -> Result<(), sunset::Error> {
        Ok(())
    }
}

/// Polls `fut` to completion, failing rather than hanging if it stalls.
///
/// Both ends of the connection are polled by the same future tree, and
/// the pipe is always ready when there is data, so a stall means a
/// deadlock rather than a missing wakeup.
pub fn run_test<F: Future>(fut: F) -> F::Output {
    const MAX_POLLS: usize = 500_000;

    let mut fut = Box::pin(fut);
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..MAX_POLLS {
        if let Poll::Ready(r) = fut.as_mut().poll(&mut cx) {
            return r;
        }
    }
    panic!("test made no progress after {MAX_POLLS} polls");
}
