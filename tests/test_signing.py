from pytest import raises
from tests import ACCOUNT, NODE_CLI, tempdir, TEST_FEE, TEST_TTL
from aeternity.signing import Account, is_signature_valid
from aeternity.utils import is_valid_hash
from aeternity import hashing
import os


def test_signing_create_transaction_signature():
    # generate a new account
    new_account = Account.generate()
    receiver_address = new_account.get_address()
    # create a spend transaction
    nonce, ttl = NODE_CLI._get_nonce_ttl(ACCOUNT.get_address(), TEST_TTL)
    tx = NODE_CLI.tx_builder.tx_spend(ACCOUNT.get_address(), receiver_address, 321, "test test ", TEST_FEE, ttl, nonce)
    tx_signed, signature, tx_hash = NODE_CLI.sign_transaction(ACCOUNT, tx)
    # this call will fail if the hashes of the transaction do not match
    NODE_CLI.broadcast_transaction(tx_signed)
    # make sure this works for very short block times
    spend_tx = NODE_CLI.get_transaction_by_hash(hash=tx_hash)
    assert spend_tx.signatures[0] == signature


def test_signing_is_valid_hash():
    # input (hash_str, prefix, expected output)
    args = [
        ('ak_me6L5SSXL4NLWv5EkQ7a16xaA145Br7oV4sz9JphZgsTsYwGC', None, True),
        ('ak_me6L5SSXL4NLWv5EkQ7a16xaA145Br7oV4sz9JphZgsTsYwGC', 'ak', True),
        ('ak_me6L5SSXL4NLWv5EkQ7a16xaA145Br7oV4sz9JphZgsTsYwGC', 'bh', False),
        ('ak_me6L5SSXL4NLWv5EkQ7a16xaA145Br7oV4sz9JphZgsTsYwYC', None, False),
        ('ak_me6L5SSXL4NLWv5EkQ7a18xaA145Br7oV4sz9JphZgsTsYwGC', None, False),
        ('bh_vzUC2jVuAfpBC3tMAHhxwxJnTFymckNYeQ5TWZua1pydabqNu', None, True),
        ('th_YqPSTzs73PiKFhFcALYWWu41uNLc6yp63ZC35jzzuJYA9PMui', None, True),
    ]

    for a in args:
        got = is_valid_hash(a[0], a[1])
        expected = a[2]
        assert got == expected


def test_signing_keystore_load():

    a = Account.from_keystore(os.path.join(os.path.dirname(os.path.realpath(__file__)), "testdata", "keystore.json"), "aeternity")
    assert a.get_address() == "ak_2hSFmdK98bhUw4ar7MUdTRzNQuMJfBFQYxdhN9kaiopDGqj3Cr"


def test_signing_keystore_save_load():
    with tempdir() as tmp_path:
        filename = ACCOUNT.save_to_keystore(tmp_path, "whatever")
        path = os.path.join(tmp_path, filename)
        print(f"\nAccount keystore is {path}")
        # now load again the same
        a = Account.from_keystore(path, "whatever")
        assert a.get_address() == ACCOUNT.get_address()
    with tempdir() as tmp_path:
        filename = "account_ks"
        filename = ACCOUNT.save_to_keystore(tmp_path, "whatever", filename=filename)
        path = os.path.join(tmp_path, filename)
        print(f"\nAccount keystore is {path}")
        # now load again the same
        a = Account.from_keystore(path, "whatever")
        assert a.get_address() == ACCOUNT.get_address()


def test_signing_keystore_save_load_wrong_pwd():
    with tempdir() as tmp_path:
        filename = ACCOUNT.save_to_keystore(tmp_path, "whatever")
        path = os.path.join(tmp_path, filename)
        print(f"\nAccount keystore is {path}")
        # now load again the same
        with raises(ValueError):
            a = Account.from_keystore(path, "nononon")
            assert a.get_address() == ACCOUNT.get_address()


def test_signing_is_signature_valid():
    sg_ae = "sg_6cXUU8rimh8B3byLHJA9SaG29uRggtyrpGi5YAFiL9cJUoVtMX4P4kpd4UPTjiGXYSaquSN3gidJ73U8CtfweQ14GFgsC"
    account_id = "ak_axjxzUJpj9siJDQKZrBFNTvQLR2JwcZoVPjgdCQdnGUtwf66r"

    sg_b64 = "KuZVJ8kK6xCmujLfd8AjU3IfENn1WwcQRA0hI/WWzyXp97zerFg9XRx/ICHcHRGmvxstsul/QEDma2uHf6DIAEcr8Vs="
    account_b64 = "TRza0pA9oaZw7tltPULKlkRaGV2qXT9vJx9q2HGY4Lom4qR3"

    msg = "aeternity".encode("utf-8")

    assert is_signature_valid(account_id, sg_ae, msg)
    assert is_signature_valid(
        hashing._base64_decode(account_b64),
        hashing._base64_decode(sg_b64),
        msg)

    msg = "wrong".encode("utf-8")
    assert not is_signature_valid(account_id, sg_ae, msg)
    assert not is_signature_valid(
        hashing._base64_decode(account_b64),
        hashing._base64_decode(sg_b64),
        msg)
