use tokio_io::{AsyncRead, AsyncWrite};
use futures::{Sink, StartSend, Poll, Stream, Async, AsyncSink};
use rustls::TLSError;
use libp2p_core::Negotiated;
use tokio_rustls::{server, client};
use std::io::Read;
use tokio_threadpool::blocking;
use std::io;

pub struct FullCodec<S>
    where
        S: AsyncRead + AsyncWrite + Send + 'static,
{
    server_stream: Option<Box<server::TlsStream<S>>>,
    client_stream: Option<Box<client::TlsStream<S>>>,
}

impl<S> FullCodec<S>
    where
        S: AsyncRead + AsyncWrite + Send + 'static,
{
    pub fn from_server(server_stream: Box<server::TlsStream<S>>) -> Self {
        FullCodec {
            server_stream: Some(server_stream),
            client_stream: None,
        }
    }

    pub fn from_client(client_stream: Box<client::TlsStream<S>>) -> Self {
        FullCodec {
            server_stream: None,
            client_stream: Some(client_stream),
        }
    }
}

impl<S> Sink for FullCodec<S>
    where
        S: AsyncRead + AsyncWrite + Send + 'static,
{
    type SinkItem = Vec<u8>;
    type SinkError = io::Error;

    #[inline]
    fn start_send(&mut self, item: Self::SinkItem) -> StartSend<Self::SinkItem, Self::SinkError> {
        println!("staring send...");
        if let Some(ref mut stream) = self.server_stream {
            return match stream.poll_write(&item) {
                Ok(Async::Ready(_)) => Ok(AsyncSink::Ready),
                _ => Ok(AsyncSink::NotReady(item))
            };
        } else if let Some(ref mut stream) = self.client_stream {
            return match stream.poll_write(&item) {
                Ok(Async::Ready(_)) => Ok(AsyncSink::Ready),
                _ => Ok(AsyncSink::NotReady(item))
            };
        }

        println!("not ready to send");
        Ok(AsyncSink::NotReady(item))
    }

    #[inline]
    fn poll_complete(&mut self) -> Poll<(), Self::SinkError> {
        println!("completing send...");
        if let Some(ref mut stream) = self.server_stream {
            return match stream.poll_flush() {
                Ok(Async::Ready(_)) => Ok(Async::Ready(())),
                _ => Ok(Async::NotReady)
            };
        } else if let Some(ref mut stream) = self.client_stream {
            return match stream.poll_flush() {
                Ok(Async::Ready(_)) => Ok(Async::Ready(())),
                _ => Ok(Async::NotReady)
            };
        }

        println!("not ready to complete send");
        Ok(Async::NotReady)
    }

    #[inline]
    fn close(&mut self) -> Poll<(), Self::SinkError> {
        Ok(Async::Ready(()))
    }
}

impl<S> Stream for FullCodec<S>
    where
        S: AsyncRead + AsyncWrite + Send,
{
    type Item = Vec<u8>;
    type Error = io::Error;

    #[inline]
    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        println!("starting to read...");
        let mut plaintext = Vec::new();
        if let Some(ref mut stream) = self.server_stream {
            return match stream.poll_read(&mut plaintext) {
                Ok(Async::Ready(0)) => Ok(Async::NotReady),
                Ok(Async::Ready(_)) => Ok(Async::Ready(Some(plaintext))),
                _ => {
                    println!("not ready to read");
                    Ok(Async::NotReady)
                }
            };
        } else if let Some(ref mut stream) = self.client_stream {
            return match stream.poll_read(&mut plaintext) {
                Ok(Async::Ready(0)) => Ok(Async::NotReady),
                Ok(Async::Ready(_)) => Ok(Async::Ready(Some(plaintext))),
                _ => {
                    println!("not ready to read");
                    Ok(Async::NotReady)
                }
            };
        }

        Ok(Async::NotReady)
    }
}
