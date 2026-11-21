use super::*;
use std::thread;

/// A stand-in for the NSM: a "document" that is the nonce then the key it
/// binds, which `verify` below reads back.
fn document_for(guest: &Guest) -> impl FnOnce(&[u8; NONCE_BYTES]) -> io::Result<Vec<u8>> + '_ {
    move |nonce| Ok([&nonce[..], &guest.public_key()[..]].concat())
}

fn verify_for(nonce: [u8; NONCE_BYTES]) -> impl FnOnce(&[u8]) -> Result<[u8; KEY_BYTES], String> {
    move |doc| {
        if doc.len() != NONCE_BYTES + KEY_BYTES || doc[..NONCE_BYTES] != nonce {
            return Err("not this nonce's document".into());
        }
        Ok(doc[NONCE_BYTES..].try_into().unwrap())
    }
}

/// One guest connection served on a thread: `accept` then, on success,
/// the session's plain end echoing back what it reads, upper-cased.
fn serve_one(guest: Arc<Guest>, s: UnixStream) -> thread::JoinHandle<Result<(), String>> {
    thread::spawn(move || {
        let session = guest.accept(s, document_for(&guest)).map_err(|e| e.to_string())?;
        let mut plain = session.into_plain().map_err(|e| e.to_string())?;
        let mut got = Vec::new();
        plain.read_to_end(&mut got).map_err(|e| e.to_string())?;
        plain.write_all(&got.to_ascii_uppercase()).map_err(|e| e.to_string())?;
        plain.shutdown(std::net::Shutdown::Write).map_err(|e| e.to_string())?;
        Ok(())
    })
}

fn round_trip(session: Session, payload: &[u8]) -> Vec<u8> {
    let mut plain = session.into_plain().unwrap();
    plain.write_all(payload).unwrap();
    plain.shutdown(std::net::Shutdown::Write).unwrap();
    let mut back = Vec::new();
    plain.read_to_end(&mut back).unwrap();
    back
}

// Goal: the home attests and claims the guest once, then resumes with the
// credential; each session carries bytes both ways, across many messages,
// and a half-close ends one direction while the other still answers.
#[test]
fn a_home_attests_once_then_resumes() {
    let guest = Arc::new(Guest::new().unwrap());
    let payload: Vec<u8> = (0..200_000u32).map(|i| b"abcdefghij"[(i % 10) as usize]).collect();

    let (home, carrier) = UnixStream::pair().unwrap();
    let served = serve_one(guest.clone(), carrier);
    let nonce = [7u8; NONCE_BYTES];
    let (session, credential) = attest(home, nonce, [9u8; KEY_BYTES], b"{}", verify_for(nonce)).unwrap();
    assert_eq!(credential.guest_key, guest.public_key());
    assert_eq!(round_trip(session, &payload), payload.to_ascii_uppercase());
    served.join().unwrap().unwrap();
    assert!(guest.claimed());

    for i in 0..3u8 {
        let (home, carrier) = UnixStream::pair().unwrap();
        let served = serve_one(guest.clone(), carrier);
        let session = resume(home, [i; NONCE_BYTES], &credential).unwrap();
        assert_eq!(round_trip(session, b"again"), b"AGAIN");
        served.join().unwrap().unwrap();
    }
}

// Goal: a guest is claimed once: a second attest is refused, and a resume
// before any attest is refused; a refused document claims nothing, so the
// next attest works.
#[test]
fn a_guest_is_claimed_once() {
    let guest = Arc::new(Guest::new().unwrap());
    let (home, carrier) = UnixStream::pair().unwrap();
    let served = serve_one(guest.clone(), carrier);
    assert!(resume(home, [1; NONCE_BYTES], &Credential { guest_key: guest.public_key(), secret: [0; KEY_BYTES] }).is_err());
    assert!(served.join().unwrap().unwrap_err().contains("no session to resume"));

    let (home, carrier) = UnixStream::pair().unwrap();
    let served = serve_one(guest.clone(), carrier);
    let refused = attest(home, [2; NONCE_BYTES], [3; KEY_BYTES], b"{}", |_| Err("PCR0 is no image of ours".to_string()));
    assert!(matches!(refused, Err(SessionError::Attestation(m)) if m.contains("PCR0")));
    assert!(served.join().unwrap().is_err());
    assert!(!guest.claimed(), "a refused document claims nothing");

    let (home, carrier) = UnixStream::pair().unwrap();
    let served = serve_one(guest.clone(), carrier);
    let (session, _) = attest(home, [4; NONCE_BYTES], [5; KEY_BYTES], b"{}", verify_for([4; NONCE_BYTES])).unwrap();
    assert_eq!(round_trip(session, b"x"), b"X");
    served.join().unwrap().unwrap();

    let (home, carrier) = UnixStream::pair().unwrap();
    let served = serve_one(guest.clone(), carrier);
    assert!(attest(home, [6; NONCE_BYTES], [7; KEY_BYTES], b"{}", verify_for([6; NONCE_BYTES])).is_err());
    assert!(served.join().unwrap().unwrap_err().contains("claimed already"));
}

// Goal: a resume without the claim's secret fails its handshake (the
// parent, which never saw the secret, cannot resume), and so does one to
// another guest's key.
#[test]
fn a_resume_needs_the_secret_and_the_key() {
    let guest = Arc::new(Guest::new().unwrap());
    let (home, carrier) = UnixStream::pair().unwrap();
    let served = serve_one(guest.clone(), carrier);
    let (session, credential) = attest(home, [1; NONCE_BYTES], [8; KEY_BYTES], b"{}", verify_for([1; NONCE_BYTES])).unwrap();
    round_trip(session, b"claim");
    served.join().unwrap().unwrap();

    let other = Guest::new().unwrap();
    for wrong in [Credential { secret: [0; KEY_BYTES], ..credential.clone() }, Credential { guest_key: other.public_key(), ..credential.clone() }] {
        let (home, carrier) = UnixStream::pair().unwrap();
        let served = serve_one(guest.clone(), carrier);
        assert!(resume(home, [2; NONCE_BYTES], &wrong).is_err());
        assert!(served.join().unwrap().is_err());
    }
}

// Goal: what the parent changes in a session is refused, not delivered: a
// flipped bit in a transport message, and a session cut without its end,
// each end the plain stream with an error rather than wrong bytes or a
// short read taken for the whole. Method: a carrier the test sits in.
#[test]
fn a_changed_or_cut_session_is_refused() {
    for cut in [false, true] {
        let guest = Arc::new(Guest::new().unwrap());
        let (home, home_side) = UnixStream::pair().unwrap();
        let (guest_side, carrier) = UnixStream::pair().unwrap();
        // The parent: a relay that flips the last byte of the first frame
        // after the handshake's, or cuts the stream there.
        let relay = thread::spawn(move || {
            let mut from = home_side;
            let mut to = guest_side;
            let mut back_from = to.try_clone().unwrap();
            let mut back_to = from.try_clone().unwrap();
            let back = thread::spawn(move || {
                let _ = io::copy(&mut back_from, &mut back_to);
            });
            let mut hello = [0u8; HELLO_BYTES];
            from.read_exact(&mut hello).unwrap();
            to.write_all(&hello).unwrap();
            for i in 0.. {
                let Ok(Some(mut frame)) = read_frame(&mut from) else { break };
                if i == 3 {
                    if cut {
                        let _ = to.shutdown(std::net::Shutdown::Both);
                        break;
                    }
                    *frame.last_mut().unwrap() ^= 1;
                }
                if write_frame(&mut to, &frame).is_err() {
                    break;
                }
            }
            let _ = back.join();
        });
        let served = thread::spawn({
            let guest = guest.clone();
            move || {
                let session = guest.accept(carrier, document_for(&guest)).map_err(|e| e.to_string())?;
                let (mut r, _w) = session.split().map_err(|e| e.to_string())?;
                let mut got = Vec::new();
                r.read_to_end(&mut got).map_err(|e| e.to_string())?;
                Ok::<_, String>(got)
            }
        });
        let nonce = [3u8; NONCE_BYTES];
        // Frames: 0 the handshake's, 1 the secret, 2 the configuration, 3
        // the data, 4 the end.
        let (session, _) = attest(home, nonce, [1; KEY_BYTES], b"{}", verify_for(nonce)).unwrap();
        let (_r, mut w) = session.split().unwrap();
        let _ = w.write_all(b"the agent's request");
        let _ = w.end();
        let got = served.join().unwrap();
        assert!(got.is_err(), "cut {cut}: {got:?}");
        drop((_r, w));
        relay.join().unwrap();
    }
}

// Goal: a hello of another version, or of no known kind, is refused before
// anything else happens.
#[test]
fn a_bad_hello_is_refused() {
    let hello = Hello { kind: Kind::Resume, nonce: [5; NONCE_BYTES] }.encode();
    assert_eq!(Hello::decode(&hello).unwrap(), Hello { kind: Kind::Resume, nonce: [5; NONCE_BYTES] });
    for (i, v) in [(0usize, 2u8), (1, 0), (1, 4)] {
        let mut b = hello;
        b[i] = v;
        assert!(matches!(Hello::decode(&b), Err(SessionError::Hello)));
    }
    assert!(format!("{:?}", Credential { guest_key: [1; 32], secret: [2; 32] }).contains("<secret>"), "a credential's secret never prints");
}

/// A claimed guest and its credential.
fn claimed(config: &[u8]) -> (Arc<Guest>, Credential) {
    let guest = Arc::new(Guest::new().unwrap());
    let (home, carrier) = UnixStream::pair().unwrap();
    let served = serve_one(guest.clone(), carrier);
    let (session, credential) = attest(home, [1; NONCE_BYTES], [2; KEY_BYTES], config, verify_for([1; NONCE_BYTES])).unwrap();
    round_trip(session, b"claim");
    served.join().unwrap().unwrap();
    (guest, credential)
}

// Goal: the claim's configuration reaches the guest, which waits for it:
// none before a claim (the wait ends empty), the home's bytes after.
#[test]
fn the_claim_carries_the_homes_configuration() {
    let unclaimed = Guest::new().unwrap();
    assert_eq!(unclaimed.wait_claimed(Duration::from_millis(50)), None);
    let (guest, _) = claimed(br#"{"ca_pem":"a CA","egress":true}"#);
    assert_eq!(guest.wait_claimed(Duration::from_millis(50)).as_deref(), Some(&br#"{"ca_pem":"a CA","egress":true}"#[..]));
}

// Goal: a claimed guest's egress connection reaches its home, which finds
// it by its key and the claim's secret, and carries bytes both ways; an
// unclaimed guest cannot dial; a home without that secret (the parent)
// fails the handshake; an egress hello is no attest or resume, and the
// other kinds are no egress.
#[test]
fn a_claimed_guest_dials_its_home() {
    let (guest, credential) = claimed(b"{}");
    let (g, h) = UnixStream::pair().unwrap();
    let home = thread::spawn(move || {
        let (session, key) = accept_egress(h, |k| (*k == credential.guest_key).then_some(credential.secret)).map_err(|e| e.to_string())?;
        let mut plain = session.into_plain().map_err(|e| e.to_string())?;
        let mut got = Vec::new();
        plain.read_to_end(&mut got).map_err(|e| e.to_string())?;
        plain.write_all(&got.to_ascii_uppercase()).map_err(|e| e.to_string())?;
        plain.shutdown(std::net::Shutdown::Write).map_err(|e| e.to_string())?;
        Ok::<_, String>(key)
    });
    let session = guest.dial_egress(g, [3; NONCE_BYTES]).unwrap();
    assert_eq!(round_trip(session, b"GET / HTTP/1.1"), b"GET / HTTP/1.1".to_ascii_uppercase());
    assert_eq!(home.join().unwrap().unwrap(), guest.public_key());

    let unclaimed = Guest::new().unwrap();
    assert!(matches!(unclaimed.dial_egress(UnixStream::pair().unwrap().0, [4; NONCE_BYTES]), Err(SessionError::Unclaimed)));

    let (g, h) = UnixStream::pair().unwrap();
    let parent = thread::spawn(move || accept_egress(h, |_| Some([0; KEY_BYTES])).is_err());
    assert!(guest.dial_egress(g, [5; NONCE_BYTES]).is_err());
    assert!(parent.join().unwrap());

    let (g, h) = UnixStream::pair().unwrap();
    let unknown = thread::spawn(move || matches!(accept_egress(h, |_| None), Err(SessionError::Unclaimed)));
    let _ = guest.dial_egress(g, [6; NONCE_BYTES]);
    assert!(unknown.join().unwrap());

    let (mut g, h) = UnixStream::pair().unwrap();
    g.write_all(&[Hello { kind: Kind::Resume, nonce: [7; NONCE_BYTES] }.encode().as_slice(), &[0u8; KEY_BYTES]].concat()).unwrap();
    assert!(matches!(accept_egress(h, |_| Some([0; KEY_BYTES])), Err(SessionError::Hello)));
    let (mut home, carrier) = UnixStream::pair().unwrap();
    home.write_all(&Hello { kind: Kind::Egress, nonce: [8; NONCE_BYTES] }.encode()).unwrap();
    assert!(matches!(guest.accept(carrier, document_for(&guest)), Err(SessionError::Hello)));
}
