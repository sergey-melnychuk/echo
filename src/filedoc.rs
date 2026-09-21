//! One Automerge document per file path (SPEC.md sections 4 and 5.1).
//!
//! Schema, from NOTES.md stage 0 design consequence 1:
//!
//! ```text
//! version: register holding "deleted" | "text:<blake3 hex>" | "blob:<manifest hex>:<size>"
//! text:    Text object, created by a deterministic genesis change, never removed
//! ```
//!
//! Every write puts a new `version` value, so concurrent writes show up as
//! concurrent values of that one register and the winner rule can see them
//! all, including a delete next to an edit (CRD-6). Text content lives in the
//! `text` object and merges character by character (CRD-2).

use anyhow::{anyhow, bail, Context, Result};
use automerge::transaction::{CommitOptions, Transactable};
use automerge::{
    ActorId, AutoCommit, ChangeHash, ObjId, ObjType, ReadDoc, ScalarValue, Value, ROOT,
};
use iroh_docs::AuthorId;

pub const KEY_VERSION: &str = "version";
pub const KEY_TEXT: &str = "text";
/// Files larger than this are never treated as text (SPEC.md section 4).
pub const MAX_TEXT_BYTES: usize = 1 << 20;

/// The content of a path as one device wrote it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Content {
    Text(String),
    Blob { manifest: [u8; 32], size: u64 },
    Deleted,
}

impl Content {
    fn version_string(&self) -> String {
        match self {
            Content::Deleted => "deleted".to_string(),
            Content::Text(text) => {
                format!("text:{}", hex(blake3::hash(text.as_bytes()).as_bytes()))
            }
            Content::Blob { manifest, size } => format!("blob:{}:{size}", hex(manifest)),
        }
    }
}

/// What a `version` value says, without the text itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VersionKind {
    Deleted,
    Text { hash: [u8; 32] },
    Blob { manifest: [u8; 32], size: u64 },
}

/// One concurrent value of the `version` register with its position in the
/// causal order: Lamport counter, then actor id (SPEC.md section 5.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Version {
    pub kind: VersionKind,
    pub counter: u64,
    pub actor: Vec<u8>,
}

impl Version {
    fn parse(text: &str, id: &ObjId) -> Result<Version> {
        let (counter, actor) = match id {
            ObjId::Id(counter, actor, _) => (*counter, actor.to_bytes().to_vec()),
            ObjId::Root => bail!("version value has the root id"),
        };
        let kind = if text == "deleted" {
            VersionKind::Deleted
        } else if let Some(hash) = text.strip_prefix("text:") {
            VersionKind::Text {
                hash: parse_hex32(hash)?,
            }
        } else if let Some(rest) = text.strip_prefix("blob:") {
            let (manifest, size) = rest
                .split_once(':')
                .ok_or_else(|| anyhow!("blob version without size: {text}"))?;
            VersionKind::Blob {
                manifest: parse_hex32(manifest)?,
                size: size
                    .parse()
                    .with_context(|| format!("blob size in {text}"))?,
            }
        } else {
            bail!("unknown version value {text:?}");
        };
        Ok(Version {
            kind,
            counter,
            actor,
        })
    }

    fn order_key(&self) -> (u64, &[u8]) {
        (self.counter, &self.actor)
    }
}

/// The state after merging: the winning content and the losing versions.
/// `losers` is empty unless CRD-3 applies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Visible {
    pub content: Content,
    pub losers: Vec<Version>,
}

impl Visible {
    pub fn is_conflict(&self) -> bool {
        !self.losers.is_empty()
    }
}

/// The Automerge document for one path.
#[derive(Debug)]
pub struct FileDoc {
    doc: AutoCommit,
}

/// The actor id for a device: its docs author id.
pub fn actor_for(author: &AuthorId) -> ActorId {
    ActorId::from(author.as_bytes())
}

/// The genesis change every file document starts from: a fixed actor, a fixed
/// timestamp and one op creating the `text` object, so that two devices which
/// create the same path independently share one text object after merging.
fn genesis() -> AutoCommit {
    let mut doc = AutoCommit::new().with_actor(ActorId::from([0u8; 32]));
    doc.put_object(ROOT, KEY_TEXT, ObjType::Text)
        .expect("genesis put_object");
    doc.commit_with(CommitOptions::default().with_time(0));
    doc
}

impl FileDoc {
    /// A fresh document for `actor`.
    pub fn new(actor: ActorId) -> FileDoc {
        FileDoc {
            doc: genesis().with_actor(actor),
        }
    }

    /// Load a snapshot, taking `actor` for future changes.
    pub fn load(bytes: &[u8], actor: ActorId) -> Result<FileDoc> {
        let doc = AutoCommit::load(bytes)
            .context("loading file document")?
            .with_actor(actor);
        Ok(FileDoc { doc })
    }

    pub fn merge_bytes(&mut self, bytes: &[u8]) -> Result<()> {
        let mut other = AutoCommit::load(bytes).context("loading file document")?;
        self.doc.merge(&mut other)?;
        Ok(())
    }

    pub fn merge(&mut self, other: &mut FileDoc) -> Result<()> {
        self.doc.merge(&mut other.doc)?;
        Ok(())
    }

    pub fn save(&mut self) -> Vec<u8> {
        self.doc.save()
    }

    /// The heads, sorted, so two documents with the same history compare equal.
    pub fn heads(&mut self) -> Vec<ChangeHash> {
        let mut heads = self.doc.get_heads();
        heads.sort();
        heads
    }

    /// The document as it was at `heads`, with the same actor. A local edit
    /// made against the content of that version is applied here and merged
    /// back, so it combines with changes that arrived since (a three-way
    /// merge, CRD-1) instead of overwriting them.
    pub fn fork_at(&mut self, heads: &[ChangeHash]) -> Result<FileDoc> {
        let actor = self.doc.get_actor().clone();
        let doc = self
            .doc
            .fork_at(heads)
            .context("forking at the base heads")?
            .with_actor(actor);
        Ok(FileDoc { doc })
    }

    /// Every concurrent value of the `version` register.
    pub fn versions(&self) -> Result<Vec<Version>> {
        let mut versions = Vec::new();
        for (value, id) in self.doc.get_all(ROOT, KEY_VERSION)? {
            let text = match &value {
                Value::Scalar(scalar) => match scalar.as_ref() {
                    ScalarValue::Str(s) => s.to_string(),
                    other => bail!("version is not a string: {other:?}"),
                },
                Value::Object(kind) => bail!("version is an object: {kind:?}"),
            };
            versions.push(Version::parse(&text, &id)?);
        }
        versions.sort_by(|a, b| a.order_key().cmp(&b.order_key()));
        Ok(versions)
    }

    /// The merged text.
    pub fn text(&self) -> Result<String> {
        match self.doc.get(ROOT, KEY_TEXT)? {
            Some((Value::Object(ObjType::Text), id)) => Ok(self.doc.text(&id)?),
            Some(other) => bail!("text is not a Text object: {other:?}"),
            None => Ok(String::new()),
        }
    }

    fn text_object(&mut self) -> Result<ObjId> {
        match self.doc.get(ROOT, KEY_TEXT)? {
            Some((Value::Object(ObjType::Text), id)) => Ok(id),
            Some(other) => bail!("text is not a Text object: {other:?}"),
            None => Ok(self.doc.put_object(ROOT, KEY_TEXT, ObjType::Text)?),
        }
    }

    /// The winner rule (SPEC.md section 5.1, CRD-2, CRD-3, CRD-6).
    pub fn visible(&self) -> Result<Visible> {
        let versions = self.versions()?;
        let live: Vec<&Version> = versions
            .iter()
            .filter(|v| v.kind != VersionKind::Deleted)
            .collect();
        if live.is_empty() {
            return Ok(Visible {
                content: Content::Deleted,
                losers: Vec::new(),
            });
        }
        if live
            .iter()
            .all(|v| matches!(v.kind, VersionKind::Text { .. }))
        {
            return Ok(Visible {
                content: Content::Text(self.text()?),
                losers: Vec::new(),
            });
        }
        // `versions` is sorted by (counter, actor): the earliest live value wins.
        let winner = live[0];
        let content = match &winner.kind {
            VersionKind::Text { .. } => Content::Text(self.text()?),
            VersionKind::Blob { manifest, size } => Content::Blob {
                manifest: *manifest,
                size: *size,
            },
            VersionKind::Deleted => unreachable!("deleted values were filtered out"),
        };
        Ok(Visible {
            content,
            losers: live[1..].iter().map(|v| (*v).clone()).collect(),
        })
    }

    /// Apply new local content on top of everything merged so far. Returns
    /// false when nothing needed to change: the register holds one value and
    /// the visible content already equals `content` (echo suppression). When
    /// the register holds several concurrent values the write always happens,
    /// which is how a write resolves a conflict (CRD-5).
    pub fn apply_local(&mut self, content: &Content) -> Result<bool> {
        let versions = self.versions()?;
        if versions.len() <= 1 && self.visible()?.content == *content {
            return Ok(false);
        }
        if let Content::Text(text) = content {
            let object = self.text_object()?;
            self.doc.update_text(&object, text)?;
        }
        self.doc.put(ROOT, KEY_VERSION, content.version_string())?;
        self.doc.commit();
        Ok(true)
    }
}

/// Merge every known snapshot of a path into one document for `actor`.
/// Returns `None` when there are no snapshots.
pub fn load_merged<'a>(
    snapshots: impl IntoIterator<Item = &'a [u8]>,
    actor: ActorId,
) -> Result<Option<FileDoc>> {
    let mut merged: Option<FileDoc> = None;
    for bytes in snapshots {
        match &mut merged {
            None => merged = Some(FileDoc::load(bytes, actor.clone())?),
            Some(doc) => doc.merge_bytes(bytes)?,
        }
    }
    Ok(merged)
}

fn hex(bytes: &[u8]) -> String {
    data_encoding::HEXLOWER.encode(bytes)
}

fn parse_hex32(text: &str) -> Result<[u8; 32]> {
    let bytes = data_encoding::HEXLOWER_PERMISSIVE
        .decode(text.as_bytes())
        .with_context(|| format!("not hex: {text}"))?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("expected 32 bytes, got {}", bytes.len()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn actor(tag: u8) -> ActorId {
        ActorId::from([tag; 32])
    }

    fn blob(tag: u8) -> Content {
        Content::Blob {
            manifest: [tag; 32],
            size: tag as u64 * 1000,
        }
    }

    fn fork(doc: &mut FileDoc, actor_tag: u8) -> FileDoc {
        FileDoc::load(&doc.save(), actor(actor_tag)).unwrap()
    }

    fn sync(a: &mut FileDoc, b: &mut FileDoc) {
        a.merge(b).unwrap();
        b.merge(a).unwrap();
    }

    #[test]
    fn genesis_is_identical_on_every_device() {
        let mut a = FileDoc::new(actor(1));
        let mut b = FileDoc::new(actor(2));
        assert_eq!(a.heads(), b.heads());
        // Independently created documents for the same path merge into one
        // text object, so both initial texts survive.
        a.apply_local(&Content::Text("from a\n".into())).unwrap();
        b.apply_local(&Content::Text("from b\n".into())).unwrap();
        sync(&mut a, &mut b);
        let text = a.text().unwrap();
        assert!(
            text.contains("from a") && text.contains("from b"),
            "{text:?}"
        );
        assert_eq!(a.visible().unwrap(), b.visible().unwrap());
        assert!(!a.visible().unwrap().is_conflict());
    }

    #[test]
    fn fresh_document_is_deleted_and_identical_content_is_a_no_op() {
        let mut doc = FileDoc::new(actor(1));
        assert_eq!(doc.visible().unwrap().content, Content::Deleted);
        assert!(!doc.apply_local(&Content::Deleted).unwrap());
        assert!(doc.apply_local(&Content::Text("hi".into())).unwrap());
        assert!(!doc.apply_local(&Content::Text("hi".into())).unwrap());
        assert!(doc.apply_local(&blob(1)).unwrap());
        assert!(!doc.apply_local(&blob(1)).unwrap());
        assert!(doc.apply_local(&Content::Deleted).unwrap());
        assert_eq!(doc.visible().unwrap().content, Content::Deleted);
        // Back to text: the old text object is reused.
        assert!(doc.apply_local(&Content::Text("hi".into())).unwrap());
        assert_eq!(doc.visible().unwrap().content, Content::Text("hi".into()));
    }

    #[test]
    fn earliest_operation_wins_and_the_rest_are_losers() {
        let mut a = FileDoc::new(actor(0xaa));
        a.apply_local(&blob(1)).unwrap();
        let mut b = fork(&mut a, 0xbb);
        // A writes twice while partitioned, B once: B's single write has the
        // lower Lamport counter and wins, even though it is "later" for A.
        a.apply_local(&blob(2)).unwrap();
        a.apply_local(&blob(3)).unwrap();
        b.apply_local(&blob(4)).unwrap();
        sync(&mut a, &mut b);
        let va = a.visible().unwrap();
        let vb = b.visible().unwrap();
        assert_eq!(va, vb);
        assert_eq!(va.content, blob(4));
        assert_eq!(va.losers.len(), 1);
        assert_eq!(
            va.losers[0].kind,
            VersionKind::Blob {
                manifest: [3; 32],
                size: 3000
            }
        );
        assert!(va.is_conflict());
        // A new write on top of the merge resolves it (CRD-5), even with the
        // winner's own content.
        assert!(a.apply_local(&blob(4)).unwrap());
        sync(&mut a, &mut b);
        assert!(!b.visible().unwrap().is_conflict());
        assert_eq!(b.visible().unwrap().content, blob(4));
    }

    #[test]
    fn ties_are_broken_by_actor_id() {
        let mut a = FileDoc::new(actor(0x02));
        a.apply_local(&blob(1)).unwrap();
        let mut b = fork(&mut a, 0x01);
        a.apply_local(&blob(2)).unwrap();
        b.apply_local(&blob(3)).unwrap();
        sync(&mut a, &mut b);
        // Same counter, lower actor id (0x01...) wins.
        assert_eq!(a.visible().unwrap().content, blob(3));
        assert_eq!(b.visible().unwrap().content, blob(3));
        assert_eq!(a.versions().unwrap()[0].actor, vec![1u8; 32]);
    }

    #[test]
    fn concurrent_edit_beats_delete() {
        let mut a = FileDoc::new(actor(1));
        a.apply_local(&blob(1)).unwrap();
        let mut b = fork(&mut a, 2);
        a.apply_local(&Content::Deleted).unwrap();
        b.apply_local(&blob(2)).unwrap();
        sync(&mut a, &mut b);
        let v = a.visible().unwrap();
        assert_eq!(v.content, blob(2));
        assert!(!v.is_conflict(), "a delete is never a loser");
        assert_eq!(v, b.visible().unwrap());

        // Delete against a concurrent text edit, too.
        let mut a = FileDoc::new(actor(1));
        a.apply_local(&Content::Text("one\n".into())).unwrap();
        let mut b = fork(&mut a, 2);
        a.apply_local(&Content::Deleted).unwrap();
        b.apply_local(&Content::Text("one\ntwo\n".into())).unwrap();
        sync(&mut a, &mut b);
        assert_eq!(
            a.visible().unwrap().content,
            Content::Text("one\ntwo\n".into())
        );
        // Delete against delete stays deleted.
        let mut c = fork(&mut a, 3);
        a.apply_local(&Content::Deleted).unwrap();
        c.apply_local(&Content::Deleted).unwrap();
        sync(&mut a, &mut c);
        assert_eq!(a.visible().unwrap().content, Content::Deleted);
    }

    #[test]
    fn concurrent_text_edits_merge_without_conflict() {
        let mut a = FileDoc::new(actor(1));
        a.apply_local(&Content::Text("hello world\n".into()))
            .unwrap();
        let mut b = fork(&mut a, 2);
        a.apply_local(&Content::Text("hello brave world\n".into()))
            .unwrap();
        b.apply_local(&Content::Text("hello world!\nsecond line\n".into()))
            .unwrap();
        sync(&mut a, &mut b);
        let v = a.visible().unwrap();
        assert_eq!(
            v.content,
            Content::Text("hello brave world!\nsecond line\n".into())
        );
        assert!(!v.is_conflict());
        assert_eq!(v, b.visible().unwrap());
        // Two version values remain until the next write collapses them.
        assert_eq!(a.versions().unwrap().len(), 2);
        assert!(a
            .apply_local(&Content::Text("hello brave world!\nsecond line\n".into()))
            .unwrap());
        assert_eq!(a.versions().unwrap().len(), 1);
    }

    #[test]
    fn text_against_blob_is_a_conflict_with_the_earliest_winning() {
        let mut a = FileDoc::new(actor(1));
        a.apply_local(&Content::Text("text\n".into())).unwrap();
        let mut b = fork(&mut a, 2);
        a.apply_local(&Content::Text("text v2\n".into())).unwrap();
        a.apply_local(&Content::Text("text v3\n".into())).unwrap();
        b.apply_local(&blob(7)).unwrap();
        sync(&mut a, &mut b);
        let v = a.visible().unwrap();
        assert_eq!(v.content, blob(7), "one write beats two");
        assert_eq!(v.losers.len(), 1);
        assert!(matches!(v.losers[0].kind, VersionKind::Text { .. }));
        assert_eq!(v, b.visible().unwrap());
        // The text is still there for the conflict copy.
        assert_eq!(a.text().unwrap(), "text v3\n");
    }

    #[test]
    fn edit_against_a_stale_base_merges_three_ways() {
        let mut a = FileDoc::new(actor(1));
        a.apply_local(&Content::Text("one\ntwo\nthree\n".into()))
            .unwrap();
        let mut b = fork(&mut a, 2);
        let base = b.heads();
        // A's edit reaches B's document before B's user saves a file that
        // was read at `base`.
        a.apply_local(&Content::Text("ONE\ntwo\nthree\n".into()))
            .unwrap();
        b.merge(&mut a).unwrap();
        assert_eq!(b.text().unwrap(), "ONE\ntwo\nthree\n");
        // Applied directly, the whole-file update would revert A's line.
        let mut wrong = FileDoc::load(&b.save(), actor(2)).unwrap();
        wrong
            .apply_local(&Content::Text("one\ntwo\nTHREE\n".into()))
            .unwrap();
        assert_eq!(wrong.text().unwrap(), "one\ntwo\nTHREE\n");
        // Applied at the base and merged, both edits survive.
        let mut at_base = b.fork_at(&base).unwrap();
        assert_eq!(at_base.text().unwrap(), "one\ntwo\nthree\n");
        assert!(at_base
            .apply_local(&Content::Text("one\ntwo\nTHREE\n".into()))
            .unwrap());
        b.merge(&mut at_base).unwrap();
        assert_eq!(b.text().unwrap(), "ONE\ntwo\nTHREE\n");
        assert!(!b.visible().unwrap().is_conflict());
        // The same base with unchanged content is a no-op.
        let mut at_base = b.fork_at(&base).unwrap();
        assert!(!at_base
            .apply_local(&Content::Text("one\ntwo\nthree\n".into()))
            .unwrap());
        // Unknown heads are an error the caller can fall back from.
        assert!(b.fork_at(&[ChangeHash([9u8; 32])]).is_err());
    }

    #[test]
    fn snapshots_round_trip_and_load_merged_merges() {
        let mut a = FileDoc::new(actor(1));
        a.apply_local(&Content::Text("a\n".into())).unwrap();
        let mut b = fork(&mut a, 2);
        b.apply_local(&Content::Text("a\nb\n".into())).unwrap();
        a.apply_local(&blob(1)).unwrap();
        let sa = a.save();
        let sb = b.save();
        let mut m = load_merged([sa.as_slice(), sb.as_slice()], actor(3))
            .unwrap()
            .unwrap();
        let mut m2 = load_merged([sb.as_slice(), sa.as_slice()], actor(3))
            .unwrap()
            .unwrap();
        assert_eq!(m.heads(), m2.heads());
        assert_eq!(m.visible().unwrap(), m2.visible().unwrap());
        assert!(load_merged(std::iter::empty(), actor(3)).unwrap().is_none());
        assert!(FileDoc::load(b"garbage", actor(1)).is_err());
    }

    #[derive(Clone, Debug)]
    enum Op {
        Text(usize, String),
        Blob(usize, u8),
        Delete(usize),
        Sync(usize, usize),
    }

    fn op() -> impl Strategy<Value = Op> {
        prop_oneof![
            (0..3usize, "[ab\n]{0,5}").prop_map(|(r, s)| Op::Text(r, s)),
            (0..3usize, 1..5u8).prop_map(|(r, m)| Op::Blob(r, m)),
            (0..3usize).prop_map(Op::Delete),
            (0..3usize, 0..3usize).prop_map(|(a, b)| Op::Sync(a, b)),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(200))]

        /// Three replicas, random edits and deliveries in random order: after
        /// a full exchange every replica shows the same visible state.
        #[test]
        fn replicas_converge(ops in prop::collection::vec(op(), 1..40)) {
            let mut docs: Vec<FileDoc> = (1..=3u8).map(|t| FileDoc::new(actor(t))).collect();
            for op in ops {
                match op {
                    Op::Text(r, s) => { docs[r].apply_local(&Content::Text(s)).unwrap(); }
                    Op::Blob(r, m) => { docs[r].apply_local(&blob(m)).unwrap(); }
                    Op::Delete(r) => { docs[r].apply_local(&Content::Deleted).unwrap(); }
                    Op::Sync(a, b) if a != b => {
                        let bytes = docs[b].save();
                        docs[a].merge_bytes(&bytes).unwrap();
                        let bytes = docs[a].save();
                        docs[b].merge_bytes(&bytes).unwrap();
                    }
                    Op::Sync(_, _) => {}
                }
            }
            for _ in 0..2 {
                for a in 0..3 {
                    for b in 0..3 {
                        if a != b {
                            let bytes = docs[b].save();
                            docs[a].merge_bytes(&bytes).unwrap();
                        }
                    }
                }
            }
            let first = docs[0].visible().unwrap();
            let heads = docs[0].heads();
            for doc in docs.iter_mut().skip(1) {
                prop_assert_eq!(doc.heads(), heads.clone());
                prop_assert_eq!(doc.visible().unwrap(), first.clone());
            }
        }
    }
}
