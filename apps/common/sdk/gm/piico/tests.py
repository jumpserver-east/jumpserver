from types import SimpleNamespace
from unittest import TestCase

from .key_management import KeyAlgorithm, KeyCategory, KeyState, PiicoKeyManager
from .zeroize import zeroize_mutable_buffer


class FakeSession:
    def __init__(self):
        self.closed = False

    def generate_ecc_key_pair(self, alg_id):
        return SimpleNamespace(
            public_key=b"\x04" + b"p" * 64,
            private_key=b"s" * 32,
        )

    def verify_sign_ecc(self, alg_id, public_key, raw_data, sign_data):
        return bool(public_key and raw_data and sign_data)

    def close(self):
        self.closed = True


class FakeDevice:
    def __init__(self, random_values=None):
        self.random_values = list(random_values or [])

    def new_session(self):
        return FakeSession()

    def generate_random(self, length):
        if self.random_values:
            return self.random_values.pop(0)
        return b"\xAA" * length

    def sm3_hmac(self, key, data):
        return bytes(key[:4]) + data[:4]


class PiicoKeyManagerZeroizeTest(TestCase):
    def test_document_key_categories_are_recorded_in_metadata(self):
        manager = PiicoKeyManager(FakeDevice())

        device_key = manager.create_device_signing_key()
        working_key = manager.create_working_key()
        session_key = manager.create_session_integrity_key()
        log_key = manager.create_log_integrity_key()

        self.assertEqual(device_key.category, KeyCategory.DEVICE_SIGNING)
        self.assertEqual(device_key.algorithm, KeyAlgorithm.SM2)
        self.assertEqual(working_key.category, KeyCategory.WORKING)
        self.assertEqual(working_key.algorithm, KeyAlgorithm.SM4)
        self.assertEqual(session_key.category, KeyCategory.SSH_SESSION_INTEGRITY)
        self.assertEqual(session_key.algorithm, KeyAlgorithm.SM3_HMAC)
        self.assertEqual(log_key.category, KeyCategory.LOG_INTEGRITY)
        self.assertEqual(log_key.algorithm, KeyAlgorithm.SM3_HMAC)

    def test_hmac_key_uses_piico_device_hmac(self):
        manager = PiicoKeyManager(FakeDevice([b"\x11" * 32]))
        metadata = manager.create_log_integrity_key()

        result = manager.compute_hmac(metadata.key_id, b"abcdef")

        self.assertEqual(result, b"\x11\x11\x11\x11abcd")

    def test_register_ukey_signing_key_and_verify_signature(self):
        manager = PiicoKeyManager(FakeDevice())
        metadata = manager.register_ukey_signing_key(
            "admin-ukey-signing",
            b"p" * 64,
        )

        result = manager.verify_ukey_signature(
            metadata.key_id,
            b"challenge",
            b"signature",
        )

        self.assertTrue(result)
        self.assertEqual(metadata.category, KeyCategory.IDENTITY_UKEY_SIGNING)
        self.assertEqual(metadata.algorithm, KeyAlgorithm.SM2)

    def test_ukey_challenge_uses_card_random(self):
        manager = PiicoKeyManager(FakeDevice([b"\x33" * 32]))

        challenge = manager.generate_ukey_challenge()

        self.assertEqual(challenge, b"\x33" * 32)

    def test_zeroize_key_overwrites_sm4_material_and_marks_destroyed(self):
        manager = PiicoKeyManager(FakeDevice())
        metadata = manager.create_sm4_key("session")
        record = manager._records[metadata.key_id]
        secret_key = record.secret_key

        destroyed = manager.zeroize_key(metadata.key_id)

        self.assertEqual(destroyed.state, KeyState.DESTROYED)
        self.assertIs(record.secret_key, secret_key)
        self.assertEqual(secret_key, bytearray(b"\x00" * 16))
        with self.assertRaises(ValueError):
            manager.enable_key(metadata.key_id)
        with self.assertRaises(ValueError):
            manager.encrypt_sm4(metadata.key_id, b"plain")

    def test_zeroize_key_supports_nonzero_fill_for_flash_semantics(self):
        manager = PiicoKeyManager(FakeDevice())
        metadata = manager.create_sm2_key_pair("device")
        record = manager._records[metadata.key_id]
        public_key = record.public_key
        private_key = record.private_key

        manager.zeroize_key(metadata.key_id, fill=0xFF)

        self.assertEqual(public_key, bytearray(b"\xFF" * 65))
        self.assertEqual(private_key, bytearray(b"\xFF" * 32))

    def test_zeroize_all_overwrites_each_record(self):
        manager = PiicoKeyManager(FakeDevice())
        first = manager.create_sm4_key("first")
        second = manager.create_sm4_key("second")
        first_secret = manager._records[first.key_id].secret_key
        second_secret = manager._records[second.key_id].secret_key

        result = manager.zeroize_all()

        self.assertEqual([item.state for item in result], [KeyState.DESTROYED, KeyState.DESTROYED])
        self.assertEqual(first_secret, bytearray(b"\x00" * 16))
        self.assertEqual(second_secret, bytearray(b"\x00" * 16))

    def test_rotate_sm4_key_zeroizes_replaced_secret(self):
        manager = PiicoKeyManager(FakeDevice([
            b"\x11" * 16,
            b"\x22" * 16,
        ]))
        metadata = manager.create_sm4_key("session")
        record = manager._records[metadata.key_id]
        old_secret_key = record.secret_key

        rotated = manager.rotate_sm4_key(metadata.key_id)

        self.assertEqual(rotated.version, 2)
        self.assertEqual(old_secret_key, bytearray(b"\x00" * 16))
        self.assertEqual(record.secret_key, bytearray(b"\x22" * 16))


class PiicoZeroizeBufferTest(TestCase):
    def test_zeroize_mutable_buffer_overwrites_bytearray_in_place(self):
        data = bytearray(b"secret")

        length = zeroize_mutable_buffer(data, fill=0xFF)

        self.assertEqual(length, 6)
        self.assertEqual(data, bytearray(b"\xFF" * 6))

    def test_zeroize_mutable_buffer_rejects_invalid_fill(self):
        with self.assertRaises(ValueError):
            zeroize_mutable_buffer(bytearray(b"secret"), fill=0x100)
