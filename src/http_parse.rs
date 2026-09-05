//! http_parse.rs — control-plane HTTP/1.1 strict-subset parser (W10).
//! Sheet: specs/http_parse.md - Zig: src/http_parse.zig (139 lines).
//!
//! Incremental PURE parser: no allocation, no sockets, zero-copy via
//! indices into the caller's buffer. Strict grammar: single-SP request
//! line, no obs-fold, no space-before-colon, Content-Length framing ONLY
//! (Transfer-Encoding is a hard refuse). Smuggling guards each get their
//! own error (exhaustive enum, no catch-all - D-049 style).

pub const HEADER_CAP: usize = 8192;
pub const BODY_CAP: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bad {
    MalformedLine,
    BadVersion,
    BadMethod,
    TransferEncoding,
    LengthRequired,
    ConflictingLength,
    ObsFold,
    SpaceBeforeColon,
    DoubleSP,
    ControlInTarget,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    Incomplete,
    HeadersTooLarge,
    BodyTooLarge,
    BadRequest(Bad),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
}

/// Zero-copy request: offsets into the caller's buffer (token/auth checks
/// compare raw bytes, never &str).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Request {
    pub method: Method,
    pub target_start: usize,
    pub target_end: usize, // target excludes ?query
    pub query_start: Option<usize>,
    pub content_length: usize,
    pub body_start: usize,
}

fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// parse(buf) - pure, zero-copy slices via indices.
pub fn parse(buf: &[u8]) -> Result<Request, ParseError> {
    // Terminator present? (CRLF CRLF). Growth past HEADER_CAP dies even
    // without terminator (slowloris size-guard, before any deadline).
    let head_end = match find_subslice(buf, b"\r\n\r\n") {
        Some(i) => i,
        None => {
            if buf.len() > HEADER_CAP {
                return Err(ParseError::HeadersTooLarge);
            }
            return Err(ParseError::Incomplete);
        }
    };
    let head = &buf[..head_end];

    // Request line: exactly two SPs, no double-SP. With zero headers the
    // line's CRLF IS the head_end boundary, so no inner CRLF exists.
    let line_end = match find_subslice(head, b"\r\n") {
        Some(i) => i,
        None => head.len(),
    };
    let line = &head[..line_end];
    let sp1 = line.iter().position(|&b| b == b' ').ok_or(ParseError::BadRequest(Bad::MalformedLine))?;
    // Strict grammar: EXACTLY two SPs in the request line. A third means a
    // spaced target smuggled past the split => DoubleSP.
    let sp_count = line.iter().filter(|&&b| b == b' ').count();
    if sp_count != 2 {
        return Err(ParseError::BadRequest(Bad::DoubleSP));
    }
    let rest = &line[sp1 + 1..];
    let sp2 = rest.iter().position(|&b| b == b' ').ok_or(ParseError::BadRequest(Bad::MalformedLine))?;
    let target = &line[sp1 + 1..sp1 + 1 + sp2];
    let version = &rest[sp2 + 1..];
    if version != b"HTTP/1.1" {
        return Err(ParseError::BadRequest(Bad::BadVersion));
    }
    let method = match &line[..sp1] {
        b"GET" => Method::Get,
        b"POST" => Method::Post,
        _ => return Err(ParseError::BadRequest(Bad::BadMethod)),
    };
    // Bare controls scanned in target.
    if target.iter().any(|&b| b < 0x21) {
        return Err(ParseError::BadRequest(Bad::ControlInTarget));
    }

    // Headers: no obs-fold (line starting with SP/HTAB), no space-before-colon.
    // Zero-header case: line_end == head.len(), so the slice is empty.
    let headers_raw = if line_end + 2 <= head.len() { &head[line_end + 2..] } else { &head[head.len()..] };
    let mut content_length: Option<usize> = None;
    let mut h = 0usize;
    while h < headers_raw.len() {
        // The LAST field ends at the terminator boundary (its CRLF opens the
        // CRLFCRLF), so a missing inner CRLF means: field = rest.
        let e = match find_subslice(&headers_raw[h..], b"\r\n") {
            Some(i) => h + i,
            None => headers_raw.len(),
        };
        let field = &headers_raw[h..e];
        if field.is_empty() {
            break;
        }
        if field[0] == b' ' || field[0] == b'\t' {
            return Err(ParseError::BadRequest(Bad::ObsFold));
        }
        let colon = field.iter().position(|&b| b == b':').ok_or(ParseError::BadRequest(Bad::MalformedLine))?;
        if colon > 0 && field[colon - 1] == b' ' {
            return Err(ParseError::BadRequest(Bad::SpaceBeforeColon));
        }
        let name = &field[..colon];
        let value = &field[colon + 1..];
        match name {
            b"Content-Length" => {
                let v = std::str::from_utf8(value)
                    .ok()
                    .and_then(|s| s.trim().parse::<usize>().ok())
                    .ok_or(ParseError::BadRequest(Bad::LengthRequired))?;
                match content_length {
                    Some(prev) if prev != v => {
                        return Err(ParseError::BadRequest(Bad::ConflictingLength))
                    }
                    _ => content_length = Some(v),
                }
            }
            b"Transfer-Encoding" => return Err(ParseError::BadRequest(Bad::TransferEncoding)),
            _ => {}
        }
        h = e + 2;
    }

    let content_length = content_length.unwrap_or(0);
    if method == Method::Post && content_length == 0 {
        return Err(ParseError::BadRequest(Bad::LengthRequired));
    }
    // Body cap enforced AT DECLARATION TIME, before any body bytes arrive.
    if content_length > BODY_CAP {
        return Err(ParseError::BodyTooLarge);
    }

    // query split (absolute offsets into buf)
    let target_abs = sp1 + 1;
    let q_rel = target.iter().position(|&b| b == b'?');
    let (tgt_end_rel, query_abs) = match q_rel {
        Some(q) => (q, Some(target_abs + q + 1)),
        None => (target.len(), None),
    };

    Ok(Request {
        method,
        target_start: target_abs,
        target_end: target_abs + tgt_end_rel,
        query_start: query_abs,
        content_length,
        body_start: head_end + 4,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(s: &str) -> Result<Request, ParseError> {
        parse(s.as_bytes())
    }

    /// :18 - body slicing takes EXACTLY clen bytes.
    #[test]
    fn body_exact_content_length() {
        let r = req("POST /x HTTP/1.1\r\nContent-Length: 4\r\n\r\nBODYTRAILING").unwrap();
        assert_eq!(r.content_length, 4);
        assert_eq!(r.body_start, "POST /x HTTP/1.1\r\nContent-Length: 4\r\n\r\n".len());
        let buf = b"POST /x HTTP/1.1\r\nContent-Length: 4\r\n\r\nBODYTRAILING";
        assert_eq!(&buf[r.body_start..r.body_start + r.content_length], b"BODY");
    }

    /// :27/:37 - fragmented feed stays Incomplete; growth past HEADER_CAP
    /// dies HeadersTooLarge even without terminator.
    #[test]
    fn incomplete_and_headers_too_large() {
        assert_eq!(req("GET /x HTTP/1.1\r\n"), Err(ParseError::Incomplete));
        let big = vec![b'a'; HEADER_CAP + 1];
        assert_eq!(parse(&big), Err(ParseError::HeadersTooLarge));
    }

    /// :55 - duplicate Content-Length only when byte-equal; conflicting refused.
    #[test]
    fn duplicate_content_length_rules() {
        assert!(req("POST / HTTP/1.1\r\nContent-Length: 3\r\nContent-Length: 3\r\n\r\nabc").is_ok());
        assert_eq!(
            req("POST / HTTP/1.1\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\nabcd"),
            Err(ParseError::BadRequest(Bad::ConflictingLength))
        );
    }

    /// :64 - obs-fold, space-before-colon, double-SP each their own error.
    #[test]
    fn smuggling_guards() {
        assert_eq!(
            req("GET /x HTTP/1.1\r\nX-A: 1\r\n  folded\r\n\r\n"),
            Err(ParseError::BadRequest(Bad::ObsFold))
        );
        assert_eq!(
            req("GET /x HTTP/1.1\r\nX-A : 1\r\n\r\n"),
            Err(ParseError::BadRequest(Bad::SpaceBeforeColon))
        );
        assert_eq!(
            req("GET  /x HTTP/1.1\r\n\r\n"),
            Err(ParseError::BadRequest(Bad::DoubleSP))
        );
    }

    /// :44 - pinned rejections: bad version, unknown method, TE present,
    /// POST without length.
    #[test]
    fn pinned_rejections() {
        assert_eq!(
            req("GET /x HTTP/1.0\r\n\r\n"),
            Err(ParseError::BadRequest(Bad::BadVersion))
        );
        assert_eq!(
            req("PUT /x HTTP/1.1\r\n\r\n"),
            Err(ParseError::BadRequest(Bad::BadMethod))
        );
        assert_eq!(
            req("GET /x HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"),
            Err(ParseError::BadRequest(Bad::TransferEncoding))
        );
        assert_eq!(
            req("POST /x HTTP/1.1\r\n\r\n"),
            Err(ParseError::BadRequest(Bad::LengthRequired))
        );
    }

    /// :83 - body cap at DECLARATION TIME.
    #[test]
    fn body_too_large_at_declaration() {
        let m = format!("POST /x HTTP/1.1\r\nContent-Length: {}\r\n\r\n", BODY_CAP + 1);
        assert_eq!(req(&m), Err(ParseError::BodyTooLarge));
    }

    /// :18 - target/query split; controls in target refused.
    #[test]
    fn target_query_and_controls() {
        let buf = b"GET /a/b?k=v HTTP/1.1\r\n\r\n";
        let r = parse(buf).unwrap();
        assert_eq!(&buf[r.target_start..r.target_end], b"/a/b");
        assert_eq!(r.query_start.unwrap(), 9); // buf index of k in /a/b?k=v
        assert_eq!(r.method, Method::Get);
        assert_eq!(
            req("GET /a b HTTP/1.1\r\n\r\n"),
            Err(ParseError::BadRequest(Bad::DoubleSP))
        );
        // true control IN the target: tab is <0x21 and not an SP delimiter
        assert_eq!(
            req("GET /a\tb HTTP/1.1\r\n\r\n"),
            Err(ParseError::BadRequest(Bad::ControlInTarget))
        );
    }
}
