//! Stage 0 spike, automerge 0.12: merge two divergent documents, read every
//! concurrent value of a register with `get_all`, and confirm that `ExId`
//! exposes the Lamport counter and actor needed for "earliest wins".
//!
//! Throwaway code. Findings go to NOTES.md.

use automerge::transaction::Transactable;
use automerge::{ActorId, AutoCommit, ObjId, ObjType, ReadDoc, ScalarValue, Value};

fn actor(tag: u8) -> ActorId {
    ActorId::from([tag; 32])
}

fn register_values(doc: &AutoCommit, key: &str) -> Vec<(String, u64, String)> {
    doc.get_all(automerge::ROOT, key)
        .unwrap()
        .into_iter()
        .map(|(value, id)| {
            let shown = match &value {
                Value::Scalar(s) => match s.as_ref() {
                    ScalarValue::Str(s) => s.to_string(),
                    ScalarValue::Bytes(b) => format!("bytes{:?}", &b[..b.len().min(2)]),
                    other => format!("{other:?}"),
                },
                Value::Object(t) => format!("object {t:?}"),
            };
            match id {
                ObjId::Id(counter, actor, _idx) => {
                    (shown, counter, actor.to_hex_string()[..4].to_string())
                }
                ObjId::Root => (shown, 0, "root".into()),
            }
        })
        .collect()
}

fn main() {
    // --- 1. register conflict on `manifest`, blob mode ---------------------
    let mut a = AutoCommit::new().with_actor(actor(0xaa));
    a.put(automerge::ROOT, "kind", "blob").unwrap();
    a.put(automerge::ROOT, "manifest", vec![1u8; 32]).unwrap();
    a.put(automerge::ROOT, "size", 10u64).unwrap();
    a.commit();
    let base = a.save();

    // B loads A's snapshot (as it would from the docs entry) and takes its own actor.
    let mut b = AutoCommit::load(&base).unwrap().with_actor(actor(0xbb));
    assert_eq!(a.get_heads(), b.get_heads(), "load reproduces heads");

    // Partitioned edits: A writes twice (two commits), B writes once.
    a.put(automerge::ROOT, "manifest", vec![2u8; 32]).unwrap();
    a.commit();
    a.put(automerge::ROOT, "manifest", vec![3u8; 32]).unwrap();
    a.commit();
    b.put(automerge::ROOT, "manifest", vec![4u8; 32]).unwrap();
    b.commit();

    let a_only = a.save();
    let b_only = b.save();

    // Merge in both directions, via snapshot bytes, as the engine would.
    let mut a_merged = AutoCommit::load(&a_only).unwrap().with_actor(actor(0xaa));
    a_merged
        .merge(&mut AutoCommit::load(&b_only).unwrap())
        .unwrap();
    let mut b_merged = AutoCommit::load(&b_only).unwrap().with_actor(actor(0xbb));
    b_merged
        .merge(&mut AutoCommit::load(&a_only).unwrap())
        .unwrap();

    let mut ha = a_merged.get_heads();
    let mut hb = b_merged.get_heads();
    ha.sort();
    hb.sort();
    assert_eq!(ha, hb, "merged heads agree");
    println!("merged heads: {} heads, equal on both sides", ha.len());

    let va = register_values(&a_merged, "manifest");
    let vb = register_values(&b_merged, "manifest");
    println!("A sees manifest values (value, counter, actor): {va:?}");
    println!("B sees manifest values (value, counter, actor): {vb:?}");
    assert_eq!(va.len(), 2, "two concurrent values survive");
    let mut sa = va.clone();
    let mut sb = vb.clone();
    sa.sort_by_key(|(_, c, act)| (*c, act.clone()));
    sb.sort_by_key(|(_, c, act)| (*c, act.clone()));
    assert_eq!(sa, sb, "same (counter, actor) ordering everywhere");
    println!("earliest by (counter, actor): {:?}", sa[0]);
    let default_a = a_merged.get(automerge::ROOT, "manifest").unwrap().unwrap();
    println!("automerge default winner: {:?}", register_values(&a_merged, "manifest").iter().find(|(v, _, _)| {
        matches!(&default_a.0, Value::Scalar(s) if format!("bytes{:?}", &match s.as_ref() { ScalarValue::Bytes(b) => b.clone(), _ => vec![] }[..2]) == *v)
    }));

    // --- 2. a later write on top of the merge resolves the conflict --------
    a_merged
        .put(automerge::ROOT, "manifest", vec![5u8; 32])
        .unwrap();
    a_merged.commit();
    b_merged.merge(&mut a_merged).unwrap();
    assert_eq!(
        register_values(&b_merged, "manifest").len(),
        1,
        "resolved after a write on top of the merge"
    );
    println!(
        "after resolving write: {:?}",
        register_values(&b_merged, "manifest")
    );

    // --- 3. delete versus concurrent edit -----------------------------------
    let mut c = AutoCommit::load(&a_merged.save())
        .unwrap()
        .with_actor(actor(0xcc));
    a_merged.put(automerge::ROOT, "kind", "deleted").unwrap();
    a_merged.commit();
    c.put(automerge::ROOT, "manifest", vec![6u8; 32]).unwrap();
    c.commit();
    a_merged.merge(&mut c).unwrap();
    println!(
        "kind after delete||edit: {:?}",
        register_values(&a_merged, "kind")
    );
    println!(
        "manifest after delete||edit: {:?}",
        register_values(&a_merged, "manifest")
    );

    // --- 4. text merge --------------------------------------------------------
    let mut t1 = AutoCommit::new().with_actor(actor(0x11));
    t1.put(automerge::ROOT, "kind", "text").unwrap();
    let text = t1
        .put_object(automerge::ROOT, "text", ObjType::Text)
        .unwrap();
    t1.update_text(&text, "hello world\n").unwrap();
    t1.commit();
    let mut t2 = AutoCommit::load(&t1.save())
        .unwrap()
        .with_actor(actor(0x22));
    let text2 = match t2.get(automerge::ROOT, "text").unwrap().unwrap() {
        (Value::Object(ObjType::Text), id) => id,
        other => panic!("unexpected {other:?}"),
    };
    t1.update_text(&text, "hello brave world\n").unwrap();
    t1.commit();
    t2.update_text(&text2, "hello world!\nsecond line\n")
        .unwrap();
    t2.commit();
    t1.merge(&mut t2).unwrap();
    t2.merge(&mut t1).unwrap();
    let s1 = t1.text(&text).unwrap();
    let s2 = t2.text(&text2).unwrap();
    println!("merged text: {s1:?}");
    assert_eq!(s1, s2);
    assert!(s1.contains("brave") && s1.contains("second line"));

    // update_text with identical content produces no pending ops.
    t1.update_text(&text, &s1).unwrap();
    println!(
        "pending ops after identical update_text: {}",
        t1.pending_ops()
    );
    assert_eq!(t1.pending_ops(), 0);
    // put with an identical scalar DOES produce an op (needs echo suppression in our code).
    let before = a_merged.get_heads();
    a_merged.put(automerge::ROOT, "size", 10u64).unwrap();
    println!(
        "pending ops after identical put: {}",
        a_merged.pending_ops()
    );
    a_merged.commit();
    println!(
        "heads changed after identical put: {}",
        a_merged.get_heads() != before
    );

    // --- 5. sizes ---------------------------------------------------------------
    println!(
        "snapshot size, blob-mode doc with 7 commits: {} bytes",
        a_merged.save().len()
    );
    println!("snapshot size, text doc: {} bytes", t1.save().len());
    followup::run();
    println!("OK");
}

#[allow(dead_code)]
mod followup {
    use super::*;

    pub fn run() {
        // Q1: while a register is conflicted, does putting the winner's value again create an op?
        let mut a = AutoCommit::new().with_actor(actor(0xaa));
        a.put(automerge::ROOT, "version", "v0").unwrap();
        a.commit();
        let mut b = AutoCommit::load(&a.save()).unwrap().with_actor(actor(0xbb));
        a.put(automerge::ROOT, "version", "vA").unwrap();
        a.commit();
        b.put(automerge::ROOT, "version", "vB").unwrap();
        b.commit();
        a.merge(&mut b).unwrap();
        let vals = register_values(&a, "version");
        println!("Q1 conflicted values: {vals:?}");
        let (winner, _) = a.get(automerge::ROOT, "version").unwrap().unwrap();
        let winner = match winner {
            Value::Scalar(s) => s.as_ref().to_string(),
            _ => unreachable!(),
        };
        a.put(automerge::ROOT, "version", winner.trim_matches('"'))
            .unwrap();
        println!(
            "Q1 pending ops after re-putting the default winner {winner}: {}",
            a.pending_ops()
        );
        a.commit();
        println!(
            "Q1 values after re-put: {:?}",
            register_values(&a, "version")
        );
        a.put(automerge::ROOT, "version", "vB").unwrap();
        println!(
            "Q1 pending ops after putting the loser's value: {}",
            a.pending_ops()
        );
        a.commit();
        println!(
            "Q1 values after putting loser value: {:?}",
            register_values(&a, "version")
        );

        // Q2: put_object(Map) on every write: concurrent writes both survive as objects?
        let mut a = AutoCommit::new().with_actor(actor(0xaa));
        let m = a
            .put_object(automerge::ROOT, "version", ObjType::Map)
            .unwrap();
        a.put(&m, "kind", "blob").unwrap();
        a.commit();
        let mut b = AutoCommit::load(&a.save()).unwrap().with_actor(actor(0xbb));
        let ma = a
            .put_object(automerge::ROOT, "version", ObjType::Map)
            .unwrap();
        a.put(&ma, "kind", "blob").unwrap();
        a.put(&ma, "manifest", vec![1u8; 32]).unwrap();
        a.commit();
        let mb = b
            .put_object(automerge::ROOT, "version", ObjType::Map)
            .unwrap();
        b.put(&mb, "kind", "blob").unwrap();
        b.put(&mb, "manifest", vec![1u8; 32]).unwrap(); // same content on both sides
        b.commit();
        a.merge(&mut b).unwrap();
        println!(
            "Q2 concurrent map objects: {:?}",
            register_values(&a, "version")
        );
        // identical content in both maps, yet two objects: our own equality check decides.
        for (_, id) in a.get_all(automerge::ROOT, "version").unwrap() {
            let kind = a.get(&id, "kind").unwrap().map(|(v, _)| format!("{v}"));
            println!(
                "   object {id:?}: kind={kind:?}, keys={:?}",
                a.keys(&id).collect::<Vec<_>>()
            );
        }
        // A put_object followed by identical-content puts is still a new op:
        let m2 = a
            .put_object(automerge::ROOT, "version", ObjType::Map)
            .unwrap();
        a.put(&m2, "kind", "blob").unwrap();
        println!(
            "Q2 pending ops for a fresh map with same content: {}",
            a.pending_ops()
        );
        a.commit();
        println!(
            "Q2 values after fresh map: {:?}",
            register_values(&a, "version").len()
        );
    }
}
