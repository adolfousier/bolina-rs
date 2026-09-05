//! W9 render: approval view for human display (render.zig port).
//!
//! BE-GRANT-07: the digest is recomputed from exactly the bytes the view
//! carries. No wire digest can enter this module.
//! BE-GRANT-07a: displayed rationale MUST be marked untrusted agent text.

use blake2::{Blake2s256, Digest};

pub const RATIONALE_UNTRUSTED_LABEL: &str = "untrusted, agent-authored";
pub const LEN_ACTION_DIGEST: usize = 8;

pub struct Rationale<'a> {
    pub text: &'a [u8],
    pub untrusted_label: &'static str,
}

pub struct ApprovalView<'a> {
    pub resource_id: &'a [u8],
    pub action: &'a [u8],
    pub action_digest: [u8; LEN_ACTION_DIGEST],
    pub rationale: Option<Rationale<'a>>,
}

fn action_digest(action: &[u8]) -> [u8; LEN_ACTION_DIGEST] {
    let mut hasher = Blake2s256::new();
    hasher.update(action);
    let result = hasher.finalize();
    let mut out = [0u8; LEN_ACTION_DIGEST];
    out.copy_from_slice(&result[..LEN_ACTION_DIGEST]);
    out
}

pub fn render_approval<'a>(
    canonical_resource_id: &'a [u8],
    action: &'a [u8],
    rationale: Option<&'a [u8]>,
) -> ApprovalView<'a> {
    ApprovalView {
        resource_id: canonical_resource_id,
        action,
        action_digest: action_digest(action),
        rationale: rationale.map(|r| Rationale {
            text: r,
            untrusted_label: RATIONALE_UNTRUSTED_LABEL,
        }),
    }
}
