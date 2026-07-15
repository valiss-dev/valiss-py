import pytest

from valiss import ValissError, nkeys


def test_create_roundtrip_seed():
    for create, prefix_char in [
        (nkeys.create_operator, "O"),
        (nkeys.create_account, "A"),
        (nkeys.create_user, "U"),
    ]:
        kp = create()
        assert kp.public_key.startswith(prefix_char)
        assert kp.seed.startswith("S" + prefix_char)
        restored = nkeys.from_seed(kp.seed)
        assert restored.public_key == kp.public_key


def test_sign_verify():
    kp = nkeys.create_account()
    sig = kp.sign(b"payload")
    kp.verify(b"payload", sig)
    nkeys.from_public_key(kp.public_key).verify(b"payload", sig)
    with pytest.raises(ValissError):
        kp.verify(b"tampered", sig)


def test_public_only_cannot_sign():
    kp = nkeys.from_public_key(nkeys.create_account().public_key)
    with pytest.raises(ValissError):
        kp.sign(b"payload")
    with pytest.raises(ValissError):
        _ = kp.seed


def test_checksum_rejected():
    key = nkeys.create_account().public_key
    corrupted = key[:-1] + ("A" if key[-1] != "A" else "B")
    with pytest.raises(ValissError):
        nkeys.decode_public(corrupted)


def test_seed_not_accepted_as_public():
    with pytest.raises(ValissError):
        nkeys.from_public_key(nkeys.create_account().seed)


def test_truncated_seed_rejected_as_valiss_error():
    # A seed truncated below 32 bytes but with a recomputed CRC passes the
    # checksum, so it must be caught by the length check and raise ValissError
    # rather than a raw cryptography.ValueError callers do not catch.
    raw = nkeys._b32decode(nkeys.create_user().seed)  # 2 prefix + 32 seed + 2 crc
    truncated = raw[:-2][:-1]  # drop the crc, then one seed byte -> 31-byte seed
    bad_seed = nkeys._b32encode(truncated + nkeys._crc16(truncated).to_bytes(2, "little"))
    with pytest.raises(ValissError, match="seed length"):
        nkeys.from_seed(bad_seed)
    with pytest.raises(ValissError, match="seed length"):
        nkeys.decode_seed(bad_seed)


def test_public_not_accepted_as_seed():
    with pytest.raises(ValissError):
        nkeys.from_seed(nkeys.create_account().public_key)


def test_validity_predicates():
    operator = nkeys.create_operator().public_key
    account = nkeys.create_account().public_key
    user = nkeys.create_user().public_key
    assert nkeys.is_valid_public_operator_key(operator)
    assert not nkeys.is_valid_public_operator_key(account)
    assert nkeys.is_valid_public_account_key(account)
    assert not nkeys.is_valid_public_account_key(user)
    assert nkeys.is_valid_public_user_key(user)
    assert not nkeys.is_valid_public_user_key(operator)
    assert not nkeys.is_valid_public_account_key("garbage")
