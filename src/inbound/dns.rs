//! DNS 入站：监听 UDP/TCP 53，接收 DNS 查询，转交内部 DNS 模块处理后回复。
//!
//! DNS 查询不走路由层，而是直接通过 `DnsQueryTx` 发给 DNS 解析器。

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{mpsc, oneshot},
};
use tracing::{debug, error, info, warn};

use crate::config::inbound::DnsInboundConfig;

// ── 公共消息类型 ──────────────────────────────────────────────────────────────

/// 一次 DNS 查询请求，附带回复通道
#[derive(Debug)]
pub struct DnsQuery {
    /// 原始 DNS wire-format 查询报文
    pub message: Bytes,
    /// 查询来源（用于日志）
    pub from: SocketAddr,
    /// 来自哪个 dns-in tag
    pub inbound_tag: String,
    /// 回复通道：DNS 模块将 wire-format 响应写回此处
    pub reply_tx: oneshot::Sender<Bytes>,
}

pub type DnsQueryTx = mpsc::Sender<DnsQuery>;

// ── 入站主结构 ────────────────────────────────────────────────────────────────

pub struct DnsInbound {
    config: DnsInboundConfig,
    /// 向 DNS 解析器发送查询
    query_tx: DnsQueryTx,
}

impl DnsInbound {
    pub fn new(config: DnsInboundConfig, query_tx: DnsQueryTx) -> Self {
        Self { config, query_tx }
    }

    pub async fn run(self) -> anyhow::Result<()> {
        let bind: SocketAddr =
            format!("{}:{}", self.config.listen, self.config.listen_port).parse()?;
        let net = self.config.network;
        let tag = Arc::new(self.config.tag.clone());

        info!(tag = %tag, addr = %bind, "dns inbound starting");

        let mut handles = vec![];

        if net.udp() {
            let sock = UdpSocket::bind(bind).await?;
            let tx = self.query_tx.clone();
            let tag = tag.clone();
            handles.push(tokio::spawn(async move { run_udp(sock, tx, tag).await }));
        }

        if net.tcp() {
            let listener = TcpListener::bind(bind).await?;
            let tx = self.query_tx.clone();
            let tag = tag.clone();
            handles.push(tokio::spawn(
                async move { run_tcp(listener, tx, tag).await },
            ));
        }

        for h in handles {
            h.await??;
        }
        Ok(())
    }
}

// ── UDP DNS ───────────────────────────────────────────────────────────────────

async fn run_udp(socket: UdpSocket, tx: DnsQueryTx, tag: Arc<String>) -> anyhow::Result<()> {
    let socket = Arc::new(socket);
    let mut buf = vec![0u8; 4096];

    loop {
        let (n, from) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                error!(err = %e, "dns udp recv error");
                continue;
            }
        };

        let message = Bytes::copy_from_slice(&buf[..n]);
        let (reply_tx, reply_rx) = oneshot::channel();

        let query = DnsQuery {
            message,
            from,
            inbound_tag: (*tag).clone(),
            reply_tx,
        };

        let sock = socket.clone();
        let tx2 = tx.clone();

        tokio::spawn(async move {
            if tx2.send(query).await.is_err() {
                return;
            }
            match reply_rx.await {
                Ok(resp) => {
                    if let Err(e) = sock.send_to(&resp, from).await {
                        warn!(from = %from, err = %e, "dns udp reply error");
                    }
                }
                Err(_) => {
                    debug!(from = %from, "dns query dropped (no reply)");
                }
            }
        });
    }
}

// ── TCP DNS（RFC 1035：2 字节长度前缀）────────────────────────────────────────

async fn run_tcp(listener: TcpListener, tx: DnsQueryTx, tag: Arc<String>) -> anyhow::Result<()> {
    loop {
        let (stream, from) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                error!(err = %e, "dns tcp accept error");
                continue;
            }
        };

        let tx2 = tx.clone();
        let tag2 = tag.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_tcp_conn(stream, from, tx2, tag2).await {
                debug!(from = %from, err = %e, "dns tcp conn error");
            }
        });
    }
}

/// 单条 TCP 连接可能携带多个 DNS 查询（流水线），全部处理完再关闭
async fn handle_tcp_conn(
    mut stream: TcpStream,
    from: SocketAddr,
    tx: DnsQueryTx,
    tag: Arc<String>,
) -> anyhow::Result<()> {
    loop {
        // DNS over TCP：先读 2 字节的消息长度
        let len = match stream.read_u16().await {
            Ok(v) => v as usize,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        };

        anyhow::ensure!(len <= 4096, "DNS TCP message too large: {len}");

        let mut msg_buf = vec![0u8; len];
        stream.read_exact(&mut msg_buf).await?;
        let message = Bytes::from(msg_buf);

        let (reply_tx, reply_rx) = oneshot::channel::<Bytes>();

        tx.send(DnsQuery {
            message,
            from,
            inbound_tag: (*tag).clone(),
            reply_tx,
        })
        .await
        .map_err(|_| anyhow::anyhow!("dns resolver closed"))?;

        let resp = reply_rx
            .await
            .map_err(|_| anyhow::anyhow!("dns resolver dropped reply"))?;

        // 回复：2 字节长度 + 报文
        let resp_len = resp.len() as u16;
        stream.write_all(&resp_len.to_be_bytes()).await?;
        stream.write_all(&resp).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造一个最小的 DNS 查询报文（查 example.com A 记录）
    fn make_dns_query() -> Bytes {
        let raw: &[u8] = &[
            0x00, 0x01, // ID
            0x01, 0x00, // flags: QR=0 OPCODE=0 RD=1
            0x00, 0x01, // QDCOUNT=1
            0x00, 0x00, // ANCOUNT=0
            0x00, 0x00, // NSCOUNT=0
            0x00, 0x00, // ARCOUNT=0
            // QNAME: example.com
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm',
            0x00, // root label
            0x00, 0x01, // QTYPE  = A
            0x00, 0x01, // QCLASS = IN
        ];
        Bytes::copy_from_slice(raw)
    }

    #[tokio::test]
    async fn dns_query_channel() {
        let (tx, mut rx) = mpsc::channel::<DnsQuery>(4);

        let msg = make_dns_query();
        let (reply_tx, reply_rx) = oneshot::channel();

        tx.send(DnsQuery {
            message: msg.clone(),
            from: "127.0.0.1:12345".parse().unwrap(),
            inbound_tag: "dns-in".into(),
            reply_tx,
        })
        .await
        .unwrap();

        let q = rx.recv().await.unwrap();
        assert_eq!(q.message, msg);
        assert_eq!(q.inbound_tag, "dns-in");

        // 模拟 DNS 模块回复
        let fake_resp = Bytes::from_static(b"\x00\x01\x81\x80fake");
        q.reply_tx.send(fake_resp.clone()).unwrap();

        let resp = reply_rx.await.unwrap();
        assert_eq!(resp, fake_resp);
    }
}
