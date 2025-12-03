//! GaussDB 兼容的 SASL 认证实现
//!
//! 这个模块提供了与 GaussDB/openGauss 兼容的 SASL 认证支持，
//! 解决了标准 PostgreSQL SASL 实现与 GaussDB 之间的兼容性问题。

use base64::display::Base64Display;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use hmac::{Hmac, Mac};
use rand::{self, Rng};
use sha2::digest::FixedOutput;
use sha2::{Digest, Sha256};
use std::fmt::Write;
use std::io;
use std::iter;
use std::mem;
use std::str;

use super::sasl::{ChannelBinding, hi};

const NONCE_LENGTH: usize = 24;

/// GaussDB 兼容的 SCRAM-SHA-256 认证处理器
///
/// 这个实现提供了与 GaussDB 特有 SASL 消息格式的兼容性，
/// 能够处理标准 PostgreSQL 和 GaussDB 之间的协议差异。
pub struct GaussDbScramSha256 {
    message: String,
    state: State,
    compatibility_mode: CompatibilityMode,
}

/// SASL 认证兼容模式
///
/// 定义了不同的 SASL 消息解析策略，以适应不同数据库系统的实现差异。
#[derive(Debug, Clone)]
pub enum CompatibilityMode {
    /// 标准 PostgreSQL 兼容模式
    Standard,
    /// GaussDB 兼容模式 - 更宽松的消息解析
    GaussDb,
    /// 自动检测模式
    Auto,
}

enum State {
    Update {
        nonce: String,
        password: Vec<u8>,
        channel_binding: ChannelBinding,
    },
    Finish {
        salted_password: [u8; 32],
        auth_message: String,
    },
    Done,
}

impl GaussDbScramSha256 {
    /// 创建新的 GaussDB 兼容 SCRAM-SHA-256 认证器
    pub fn new(password: &[u8], channel_binding: ChannelBinding) -> Self {
        Self::new_with_compatibility(password, channel_binding, CompatibilityMode::GaussDb)
    }

    /// 创建指定兼容模式的认证器
    pub fn new_with_compatibility(
        password: &[u8], 
        channel_binding: ChannelBinding,
        compatibility_mode: CompatibilityMode
    ) -> Self {
        let mut rng = rand::rng();
        let nonce = (0..NONCE_LENGTH)
            .map(|_| {
                let mut v = rng.random_range(0x21u8..0x7e);
                if v == 0x2c {
                    v = 0x7e
                }
                v as char
            })
            .collect::<String>();

        Self::new_inner(password, channel_binding, nonce, compatibility_mode)
    }

    fn new_inner(
        password: &[u8], 
        channel_binding: ChannelBinding, 
        nonce: String,
        compatibility_mode: CompatibilityMode
    ) -> Self {
        let normalized_password = normalize(password);
        
        GaussDbScramSha256 {
            message: format!("{}n=,r={}", channel_binding.gs2_header(), nonce),
            state: State::Update {
                nonce,
                password: normalized_password,
                channel_binding,
            },
            compatibility_mode,
        }
    }

    /// 返回应该发送给后端的消息
    pub fn message(&self) -> &[u8] {
        if let State::Done = self.state {
            panic!("invalid SCRAM state");
        }
        self.message.as_bytes()
    }

    /// 使用 GaussDB 兼容的解析器更新状态
    pub fn update(&mut self, message: &[u8]) -> io::Result<()> {
        let (client_nonce, password, channel_binding) =
            match mem::replace(&mut self.state, State::Done) {
                State::Update {
                    nonce,
                    password,
                    channel_binding,
                } => (nonce, password, channel_binding),
                _ => return Err(io::Error::other("invalid SCRAM state")),
            };

        let message_str = str::from_utf8(message)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

        // 使用 GaussDB 兼容的解析器
        let parsed = GaussDbSaslParser::new(message_str, &self.compatibility_mode)
            .server_first_message()?;

        if !parsed.nonce.starts_with(&client_nonce) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid nonce"));
        }

        let salt = match STANDARD.decode(parsed.salt) {
            Ok(salt) => salt,
            Err(e) => return Err(io::Error::new(io::ErrorKind::InvalidInput, e)),
        };

        let salted_password = hi(&password, &salt, parsed.iteration_count);

        let mut hmac = Hmac::<Sha256>::new_from_slice(&salted_password)
            .expect("HMAC is able to accept all key sizes");
        hmac.update(b"Client Key");
        let client_key = hmac.finalize().into_bytes();

        let mut hash = Sha256::default();
        hash.update(client_key.as_slice());
        let stored_key = hash.finalize_fixed();

        let mut cbind_input = vec![];
        cbind_input.extend(channel_binding.gs2_header().as_bytes());
        cbind_input.extend(channel_binding.cbind_data());
        let cbind_input = STANDARD.encode(&cbind_input);

        self.message.clear();
        write!(&mut self.message, "c={},r={}", cbind_input, parsed.nonce).unwrap();

        let auth_message = format!("n=,r={},{},{}", client_nonce, message_str, self.message);

        let mut hmac = Hmac::<Sha256>::new_from_slice(&stored_key)
            .expect("HMAC is able to accept all key sizes");
        hmac.update(auth_message.as_bytes());
        let client_signature = hmac.finalize().into_bytes();

        let mut client_proof = client_key;
        for (proof, signature) in client_proof.iter_mut().zip(client_signature) {
            *proof ^= signature;
        }

        write!(
            &mut self.message,
            ",p={}",
            Base64Display::new(&client_proof, &STANDARD)
        )
        .unwrap();

        self.state = State::Finish {
            salted_password,
            auth_message,
        };
        Ok(())
    }

    /// 完成认证过程
    pub fn finish(&mut self, message: &[u8]) -> io::Result<()> {
        let (salted_password, auth_message) = match mem::replace(&mut self.state, State::Done) {
            State::Finish {
                salted_password,
                auth_message,
            } => (salted_password, auth_message),
            _ => return Err(io::Error::other("invalid SCRAM state")),
        };

        let message_str = str::from_utf8(message)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

        // 使用 GaussDB 兼容的解析器
        let parsed = GaussDbSaslParser::new(message_str, &self.compatibility_mode)
            .server_final_message()?;

        let verifier = match parsed {
            ServerFinalMessage::Error(e) => {
                return Err(io::Error::other(format!("SCRAM error: {}", e)));
            }
            ServerFinalMessage::Verifier(verifier) => verifier,
        };

        let verifier = match STANDARD.decode(verifier) {
            Ok(verifier) => verifier,
            Err(e) => return Err(io::Error::new(io::ErrorKind::InvalidInput, e)),
        };

        let mut hmac = Hmac::<Sha256>::new_from_slice(&salted_password)
            .expect("HMAC is able to accept all key sizes");
        hmac.update(b"Server Key");
        let server_key = hmac.finalize().into_bytes();

        let mut hmac = Hmac::<Sha256>::new_from_slice(&server_key)
            .expect("HMAC is able to accept all key sizes");
        hmac.update(auth_message.as_bytes());
        hmac.verify_slice(&verifier)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "SCRAM verification error"))
    }
}

/// GaussDB 兼容的 SASL 消息解析器
struct GaussDbSaslParser<'a> {
    s: &'a str,
    it: iter::Peekable<str::CharIndices<'a>>,
    compatibility_mode: &'a CompatibilityMode,
}

impl<'a> GaussDbSaslParser<'a> {
    fn new(s: &'a str, compatibility_mode: &'a CompatibilityMode) -> Self {
        GaussDbSaslParser {
            s,
            it: s.char_indices().peekable(),
            compatibility_mode,
        }
    }

    /// GaussDB 兼容的 EOF 检查
    /// 
    /// 与标准实现不同，这个版本在 GaussDB 模式下更宽松地处理尾随数据
    fn eof(&mut self) -> io::Result<()> {
        match self.compatibility_mode {
            CompatibilityMode::Standard => {
                // 标准模式：严格检查 EOF
                match self.it.peek() {
                    Some(&(i, _)) => Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("unexpected trailing data at byte {}", i),
                    )),
                    None => Ok(()),
                }
            }
            CompatibilityMode::GaussDb | CompatibilityMode::Auto => {
                // GaussDB 模式：跳过尾随的空白字符和控制字符直到真正结束
                while let Some(&(_, c)) = self.it.peek() {
                    if c.is_whitespace() || c == '\0' || c.is_control() {
                        self.it.next();
                    } else {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!("unexpected trailing data: '{}'", c),
                        ));
                    }
                }
                Ok(())
            }
        }
    }

    // 其他解析方法保持与原始实现相同...
    fn eat(&mut self, target: char) -> io::Result<()> {
        match self.it.next() {
            Some((_, c)) if c == target => Ok(()),
            Some((i, c)) => {
                let m = format!(
                    "unexpected character at byte {}: expected `{}` but got `{}`",
                    i, target, c
                );
                Err(io::Error::new(io::ErrorKind::InvalidInput, m))
            }
            None => Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "unexpected EOF",
            )),
        }
    }

    fn take_while<F>(&mut self, f: F) -> io::Result<&'a str>
    where
        F: Fn(char) -> bool,
    {
        let start = match self.it.peek() {
            Some(&(i, _)) => i,
            None => return Ok(""),
        };

        loop {
            match self.it.peek() {
                Some(&(_, c)) if f(c) => {
                    self.it.next();
                }
                Some(&(i, _)) => return Ok(&self.s[start..i]),
                None => return Ok(&self.s[start..]),
            }
        }
    }

    fn printable(&mut self) -> io::Result<&'a str> {
        self.take_while(|c| matches!(c, '\x21'..='\x2b' | '\x2d'..='\x7e'))
    }

    fn nonce(&mut self) -> io::Result<&'a str> {
        self.eat('r')?;
        self.eat('=')?;
        self.printable()
    }

    fn base64(&mut self) -> io::Result<&'a str> {
        self.take_while(|c| matches!(c, 'a'..='z' | 'A'..='Z' | '0'..='9' | '/' | '+' | '='))
    }

    fn salt(&mut self) -> io::Result<&'a str> {
        self.eat('s')?;
        self.eat('=')?;
        self.base64()
    }

    fn posit_number(&mut self) -> io::Result<u32> {
        let n = self.take_while(|c| c.is_ascii_digit())?;
        n.parse()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))
    }

    fn iteration_count(&mut self) -> io::Result<u32> {
        self.eat('i')?;
        self.eat('=')?;
        self.posit_number()
    }

    fn server_first_message(&mut self) -> io::Result<ServerFirstMessage<'a>> {
        let nonce = self.nonce()?;
        self.eat(',')?;
        let salt = self.salt()?;
        self.eat(',')?;
        let iteration_count = self.iteration_count()?;
        
        // 在 GaussDB 模式下允许额外的数据（更宽松的处理）
        if matches!(self.compatibility_mode, CompatibilityMode::GaussDb | CompatibilityMode::Auto) {
            // 忽略任何额外的字段，直到EOF
            while self.it.peek().is_some() {
                // 检查是否是有效的字段格式（键=值）
                let _pos = match self.it.peek() {
                    Some(&(pos, _)) => pos,
                    None => break,
                };
                
                // 尝试解析字段
                match self.try_parse_extra_field() {
                    Ok(true) => continue, // 成功解析了一个额外字段
                    Ok(false) => break,   // 不是额外字段格式，停止解析
                    Err(_) => break,      // 解析出错，停止解析
                }
            }
        }
        
        self.eof()?;

        Ok(ServerFirstMessage {
            nonce,
            salt,
            iteration_count,
        })
    }
    
    /// 尝试解析一个额外的字段（用于兼容 GaussDB 的扩展格式）
    fn try_parse_extra_field(&mut self) -> io::Result<bool> {
        // 保存当前位置以便回退
        let saved_it = self.it.clone();
        
        // 尝试解析 "key=value" 格式
        match self.take_while(|c| c.is_alphabetic() || c == '_') {
            Ok(key) if !key.is_empty() => {
                // 有键名，检查等号
                if self.eat('=').is_ok() {
                    // 有等号，尝试读取值
                    match self.take_while(|c| c != ',' && c != '\0' && !c.is_control()) {
                        Ok(_value) => {
                            // 成功读取值，吃掉分隔符（如果有的话）
                            if let Some(&(_, ',')) = self.it.peek() {
                                self.it.next(); // 吃掉逗号
                            }
                            Ok(true) // 成功解析一个字段
                        }
                        Err(_) => {
                            // 回退并返回false
                            self.it = saved_it;
                            Ok(false)
                        }
                    }
                } else {
                    // 没有等号，回退并返回false
                    self.it = saved_it;
                    Ok(false)
                }
            }
            _ => {
                // 没有有效键名，回退并返回false
                self.it = saved_it;
                Ok(false)
            }
        }
    }

    fn value(&mut self) -> io::Result<&'a str> {
        self.take_while(|c| !matches!(c, '\0' | '=' | ','))
    }

    fn server_error(&mut self) -> io::Result<Option<&'a str>> {
        match self.it.peek() {
            Some(&(_, 'e')) => {}
            _ => return Ok(None),
        }

        self.eat('e')?;
        self.eat('=')?;
        self.value().map(Some)
    }

    fn verifier(&mut self) -> io::Result<&'a str> {
        self.eat('v')?;
        self.eat('=')?;
        self.base64()
    }

    fn server_final_message(&mut self) -> io::Result<ServerFinalMessage<'a>> {
        let message = match self.server_error()? {
            Some(error) => ServerFinalMessage::Error(error),
            None => ServerFinalMessage::Verifier(self.verifier()?),
        };
        
        // 在 GaussDB 模式下允许尾随数据
        if matches!(self.compatibility_mode, CompatibilityMode::GaussDb | CompatibilityMode::Auto) {
            // 消费所有剩余字符直到EOF
            while self.it.peek().is_some() {
                self.it.next();
            }
        }
        
        self.eof()?;
        Ok(message)
    }
}

struct ServerFirstMessage<'a> {
    nonce: &'a str,
    salt: &'a str,
    iteration_count: u32,
}

enum ServerFinalMessage<'a> {
    Error(&'a str),
    Verifier(&'a str),
}

// since postgres passwords are not required to exclude saslprep-prohibited
// characters or even be valid UTF8, we run saslprep if possible and otherwise
// return the raw password.
fn normalize(pass: &[u8]) -> Vec<u8> {
    let pass = match str::from_utf8(pass) {
        Ok(pass) => pass,
        Err(_) => return pass.to_vec(),
    };

    match stringprep::saslprep(pass) {
        Ok(pass) => pass.into_owned().into_bytes(),
        Err(_) => pass.as_bytes().to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gaussdb_compatibility_mode() {
        // 测试 GaussDB 兼容模式能够处理带有尾随数据的消息
        let message_with_trailing = "r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096\r\n";

        let mut parser = GaussDbSaslParser::new(message_with_trailing, &CompatibilityMode::GaussDb);
        let result = parser.server_first_message();

        assert!(result.is_ok(), "GaussDB 兼容模式应该能够处理尾随数据");

        let parsed = result.unwrap();
        assert_eq!(parsed.nonce, "fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j");
        assert_eq!(parsed.salt, "QSXCR+Q6sek8bf92");
        assert_eq!(parsed.iteration_count, 4096);
    }

    #[test]
    fn test_standard_mode_strict() {
        // 测试标准模式严格检查尾随数据
        let message_with_trailing = "r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096\r\n";

        let mut parser = GaussDbSaslParser::new(message_with_trailing, &CompatibilityMode::Standard);
        let result = parser.server_first_message();

        assert!(result.is_err(), "标准模式应该拒绝带有尾随数据的消息");
    }

    #[test]
    fn test_auto_mode_detection() {
        // 测试自动模式检测
        let clean_message = "r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096";
        let mut parser = GaussDbSaslParser::new(clean_message, &CompatibilityMode::Auto);
        let result = parser.server_first_message();
        assert!(result.is_ok(), "自动模式应该处理干净的消息");

        let message_with_trailing = "r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096\r\n";
        let mut parser = GaussDbSaslParser::new(message_with_trailing, &CompatibilityMode::Auto);
        let result = parser.server_first_message();
        assert!(result.is_ok(), "自动模式应该处理带尾随数据的消息");
    }

    #[test]
    fn test_scram_sha256_creation() {
        // 测试 SCRAM-SHA-256 认证器创建
        let password = b"test_password";
        let channel_binding = ChannelBinding::unsupported();

        let scram = GaussDbScramSha256::new(password, channel_binding);
        let message = scram.message();

        assert!(!message.is_empty(), "SCRAM 消息不应为空");
        assert!(std::str::from_utf8(message).is_ok(), "SCRAM 消息应该是有效的 UTF-8");
    }

    #[test]
    fn test_scram_sha256_with_compatibility_mode() {
        // 测试不同兼容模式下的 SCRAM-SHA-256 创建
        let password = b"test_password";
        let _channel_binding = ChannelBinding::unsupported();

        let modes = [
            CompatibilityMode::Standard,
            CompatibilityMode::GaussDb,
            CompatibilityMode::Auto,
        ];

        for mode in &modes {
            let scram = GaussDbScramSha256::new_with_compatibility(password, ChannelBinding::unsupported(), mode.clone());
            let message = scram.message();

            assert!(!message.is_empty(), "SCRAM 消息不应为空 (模式: {:?})", mode);
            assert!(std::str::from_utf8(message).is_ok(), "SCRAM 消息应该是有效的 UTF-8 (模式: {:?})", mode);
        }
    }

    #[test]
    fn test_server_final_message_parsing() {
        // 测试服务器最终消息解析
        let verifier_message = "v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=";
        let mut parser = GaussDbSaslParser::new(verifier_message, &CompatibilityMode::GaussDb);
        let result = parser.server_final_message();

        assert!(result.is_ok(), "应该能够解析验证器消息");
        match result.unwrap() {
            ServerFinalMessage::Verifier(v) => {
                assert_eq!(v, "6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=");
            }
            ServerFinalMessage::Error(_) => panic!("不应该是错误消息"),
        }

        let error_message = "e=invalid-proof";
        let mut parser = GaussDbSaslParser::new(error_message, &CompatibilityMode::GaussDb);
        let result = parser.server_final_message();

        assert!(result.is_ok(), "应该能够解析错误消息");
        match result.unwrap() {
            ServerFinalMessage::Error(e) => {
                assert_eq!(e, "invalid-proof");
            }
            ServerFinalMessage::Verifier(_) => panic!("不应该是验证器消息"),
        }
    }

    #[test]
    fn test_parser_edge_cases() {
        // 测试解析器边界情况
        let test_cases = vec![
            ("", "空消息"),
            ("invalid", "无效格式"),
            ("r=", "空 nonce"),
            ("r=test,s=", "空 salt"),
            ("r=test,s=salt,i=", "空迭代次数"),
            ("r=test,s=salt,i=abc", "无效迭代次数"),
        ];

        for (message, description) in test_cases {
            let mut parser = GaussDbSaslParser::new(message, &CompatibilityMode::GaussDb);
            let result = parser.server_first_message();
            assert!(result.is_err(), "应该拒绝无效消息: {}", description);
        }
    }

    #[test]
    fn test_whitespace_handling() {
        // 测试空白字符处理
        let test_cases = vec![
            "r=test,s=salt,i=4096 ",      // 尾随空格
            "r=test,s=salt,i=4096\t",     // 尾随制表符
            "r=test,s=salt,i=4096\n",     // 尾随换行符
            "r=test,s=salt,i=4096\r\n",   // 尾随回车换行符
            "r=test,s=salt,i=4096   \t\n", // 混合空白字符
        ];

        for message in test_cases {
            // GaussDB 模式应该处理这些情况
            let mut parser = GaussDbSaslParser::new(message, &CompatibilityMode::GaussDb);
            let result = parser.server_first_message();
            assert!(result.is_ok(), "GaussDB 模式应该处理尾随空白: '{}'", message.escape_debug());

            // 标准模式应该拒绝
            let mut parser = GaussDbSaslParser::new(message, &CompatibilityMode::Standard);
            let result = parser.server_first_message();
            assert!(result.is_err(), "标准模式应该拒绝尾随空白: '{}'", message.escape_debug());
        }
    }
}
