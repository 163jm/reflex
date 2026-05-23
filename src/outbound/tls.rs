//! 共用 TLS 连接器，供 VLESS 和 Hy2 复用。

use std::{io::BufReader, sync::Arc};

use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
    ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme,
};
use tokio::net::TcpStream;
use tokio_rustls::{client::TlsStream, TlsConnector};

use crate::config::outbound::TlsConfig;

/// 根据配置构建 rustls ClientConfig
pub fn build_client_config(tls: &TlsConfig) -> anyhow::Result<Arc<ClientConfig>> {
    let mut root_store = RootCertStore::empty();

    if let Some(ca_path) = &tls.ca_path {
        // 自定义 CA
        let ca_data = std::fs::read(ca_path)?;
        let mut reader = BufReader::new(ca_data.as_slice());
        for cert in rustls_pemfile::certs(&mut reader) {
            root_store.add(cert?)?;
        }
    } else {
        // 系统根证书
        let native = rustls_native_certs::load_native_certs();
        for cert in native.certs {
            // 忽略单个证书加载失败（系统证书库可能有无效条目）
            let _ = root_store.add(cert);
        }
    }

    let config = if tls.insecure {
        // 跳过证书验证（调试用）
        ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth()
    } else {
        let builder = ClientConfig::builder().with_root_certificates(root_store);

        builder.with_no_client_auth()
    };

    Ok(Arc::new(config))
}

/// 在已有 TCP 流上建立 TLS 连接
pub async fn connect_tls(
    stream: TcpStream,
    server_name: &str,
    config: Arc<ClientConfig>,
) -> anyhow::Result<TlsStream<TcpStream>> {
    let connector = TlsConnector::from(config);
    let sni = ServerName::try_from(server_name.to_string())
        .map_err(|_| anyhow::anyhow!("invalid server name: {server_name}"))?;
    let tls = connector.connect(sni, stream).await?;
    Ok(tls)
}

// ── 证书验证跳过（insecure 模式）────────────────────────────────────────────

#[derive(Debug)]
pub struct NoVerifier;

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}
