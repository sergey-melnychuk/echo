//! Stage 0 spike, biscuit-auth 6: build the vault token, attenuate it to an
//! audience and an expiry, serialize, verify under the root key, and run the
//! authorizer with ambient `endpoint` and `time` facts.
//!
//! Throwaway code. Findings go to NOTES.md.

use std::time::{Duration, SystemTime};

use biscuit_auth::builder::Algorithm;
use biscuit_auth::macros::{authorizer, biscuit, block};
use biscuit_auth::{Biscuit, KeyPair, PrivateKey, PublicKey};

fn authorize(
    token: &Biscuit,
    vault: &str,
    endpoint: &str,
    now: SystemTime,
) -> Result<usize, biscuit_auth::error::Token> {
    let mut authorizer = authorizer!(
        r#"
        endpoint({endpoint});
        time({now});
        check if vault({vault});
        allow if right("sync");
        "#,
        endpoint = endpoint,
        now = now,
        vault = vault,
    )
    .build(token)?;
    authorizer.authorize()
}

fn main() {
    let root = KeyPair::new();
    let vault = "ns-1234";
    let now = SystemTime::now();
    let exp = now + Duration::from_secs(3600);

    // Authority block, minted at `init`.
    let authority = biscuit!(
        r#"
        vault({vault});
        right("sync");
        "#,
        vault = vault,
    )
    .build(&root)
    .unwrap();
    println!(
        "authority token: {} bytes",
        authority.to_vec().unwrap().len()
    );

    // Attenuation at invite time: bind to an endpoint id and an expiry.
    let audience = "ep-alice";
    let invite = authority
        .append(block!(
            r#"
            check if endpoint($e), $e == {audience};
            check if time($t), $t < {exp};
            "#,
            audience = audience,
            exp = exp,
        ))
        .unwrap();
    let wire = invite.to_vec().unwrap();
    println!(
        "attenuated token: {} bytes, base64 {} chars",
        wire.len(),
        invite.to_base64().unwrap().len()
    );
    println!("--- token ---\n{}", invite.print());

    // Root public key round trip through hex, as stored in config and invites.
    let hex = root.public().to_bytes_hex();
    let pk = PublicKey::from_bytes_hex(&hex, Algorithm::Ed25519).unwrap();
    assert_eq!(pk, root.public());
    // Root private key round trip through bytes, as stored under .vault/.
    let sk_bytes = root.private().to_bytes();
    let sk = PrivateKey::from_bytes(&sk_bytes, Algorithm::Ed25519).unwrap();
    let root_again = KeyPair::from(&sk);
    assert_eq!(root_again.public(), root.public());

    // Receiver: verify signature chain under the root public key, then authorize.
    let received = Biscuit::from(&wire, pk).unwrap();
    assert!(
        authorize(&received, vault, audience, now).is_ok(),
        "valid token accepted"
    );
    println!("valid token: accepted");

    let err = authorize(&received, vault, "ep-mallory", now).unwrap_err();
    println!("wrong endpoint: {err}");
    let err = authorize(&received, vault, audience, exp + Duration::from_secs(1)).unwrap_err();
    println!("expired: {err}");
    let err = authorize(&received, "ns-other", audience, now).unwrap_err();
    println!("other vault: {err}");
    let other_root = KeyPair::new();
    let err = Biscuit::from(&wire, other_root.public()).unwrap_err();
    println!("other root key: {err}");

    // Delegation: the invitee attenuates further for a third device.
    let delegated = received
        .append(block!(
            r#"
            check if endpoint($e), $e == {audience};
            check if time($t), $t < {exp};
            "#,
            audience = "ep-bob",
            exp = now + Duration::from_secs(600),
        ))
        .unwrap();
    let delegated = Biscuit::from(delegated.to_vec().unwrap(), root.public()).unwrap();
    // Every block's checks apply, so the delegated token is valid for nobody:
    // block 1 demands ep-alice and block 2 demands ep-bob.
    let err = authorize(&delegated, vault, "ep-bob", now).unwrap_err();
    println!("delegated with conflicting audience checks: {err}");

    // The right way to delegate: the owner mints a token bound to nothing but the
    // expiry, and each hop narrows the audience. Simulate: an unbound token.
    let unbound = authority
        .append(block!(r#"check if time($t), $t < {exp};"#, exp = exp))
        .unwrap();
    let narrowed = unbound
        .append(block!(r#"check if endpoint($e), $e == {a};"#, a = "ep-bob"))
        .unwrap();
    let narrowed = Biscuit::from(narrowed.to_vec().unwrap(), root.public()).unwrap();
    assert!(authorize(&narrowed, vault, "ep-bob", now).is_ok());
    assert!(authorize(&narrowed, vault, "ep-alice", now).is_err());
    println!("delegation by narrowing: ok");

    // Widening attempt: a block adds a fact. Block facts are not visible to the
    // authorizer's policy by default (scoped to the block), so it changes nothing.
    let widened = Biscuit::from(&wire, root.public())
        .unwrap()
        .append(block!(
            r#"right("sync"); right("admin"); vault({v});"#,
            v = "ns-other"
        ))
        .unwrap();
    let widened = Biscuit::from(widened.to_vec().unwrap(), root.public()).unwrap();
    let err = authorize(&widened, "ns-other", audience, now).unwrap_err();
    println!("widened vault fact ignored: {err}");
    // Could a stripped token (without the authority right) be widened?
    let no_right = biscuit!(r#"vault({vault});"#, vault = vault)
        .build(&root)
        .unwrap();
    let widened2 = no_right.append(block!(r#"right("sync");"#)).unwrap();
    let err = authorize(&widened2, vault, audience, now).unwrap_err();
    println!("right added in an attenuation block ignored: {err}");

    // Oversized token guard: how big does a token get with many blocks?
    let mut big = authority.clone();
    for i in 0..20 {
        big = big
            .append(block!(
                r#"check if time($t), $t < {exp};"#,
                exp = exp + Duration::from_secs(i)
            ))
            .unwrap();
    }
    println!(
        "token with 21 blocks: {} bytes",
        big.to_vec().unwrap().len()
    );
    println!("OK");
}
