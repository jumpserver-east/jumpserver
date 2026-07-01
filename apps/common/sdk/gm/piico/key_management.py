"""
Piico key management facade.
"""

import base64
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, Iterable, Optional

from .const import SGD_SM2, SGD_SM4_ECB
from .zeroize import zeroize_mutable_buffer


class KeyAlgorithm(str, Enum):
    SM2 = "sm2"
    SM3_HMAC = "sm3_hmac"
    SM4 = "sm4"


class KeyCategory(str, Enum):
    DEVICE_SIGNING = "device_signing"
    DEVICE_ENCRYPTION = "device_encryption"
    PRE_MASTER = "pre_master"
    MASTER = "master"
    WORKING = "working"
    SSH_SESSION_ENCRYPTION = "ssh_session_encryption"
    SSH_SESSION_INTEGRITY = "ssh_session_integrity"
    LOG_ENCRYPTION = "log_encryption"
    LOG_INTEGRITY = "log_integrity"
    IDENTITY_UKEY_SIGNING = "identity_ukey_signing"
    IDENTITY_UKEY_ENCRYPTION = "identity_ukey_encryption"
    BACKUP = "backup"


class KeyState(str, Enum):
    ACTIVE = "active"
    DISABLED = "disabled"
    DESTROYED = "destroyed"


@dataclass(frozen=True)
class KeyMetadata:
    key_id: str
    label: str
    category: KeyCategory
    algorithm: KeyAlgorithm
    state: KeyState
    version: int
    created_at: datetime
    updated_at: datetime
    usage: tuple[str, ...] = field(default_factory=tuple)


@dataclass
class _KeyRecord:
    metadata: KeyMetadata
    public_key: bytearray = field(default_factory=bytearray)
    private_key: bytearray = field(default_factory=bytearray)
    secret_key: bytearray = field(default_factory=bytearray)


class PiicoKeyManager:
    """
    Key manager around the existing Piico device wrapper.
    """

    def __init__(self, device):
        self.device = device
        self._records: Dict[str, _KeyRecord] = {}

    def create_sm2_key_pair(
            self,
            label: str,
            usage: Iterable[str] = ("encrypt", "verify"),
            category: KeyCategory = KeyCategory.DEVICE_SIGNING,
    ) -> KeyMetadata:
        session = self.device.new_session()
        try:
            key_pair = session.generate_ecc_key_pair(SGD_SM2)
        finally:
            session.close()

        key_id = self._new_key_id()
        now = self._now()
        metadata = KeyMetadata(
            key_id=key_id,
            label=label,
            category=category,
            algorithm=KeyAlgorithm.SM2,
            state=KeyState.ACTIVE,
            version=1,
            created_at=now,
            updated_at=now,
            usage=tuple(usage),
        )
        self._records[key_id] = _KeyRecord(
            metadata=metadata,
            public_key=bytearray(key_pair.public_key),
            private_key=bytearray(key_pair.private_key),
        )
        return metadata

    def create_sm4_key(
            self,
            label: str,
            length: int = 16,
            usage: Iterable[str] = ("encrypt", "decrypt"),
            category: KeyCategory = KeyCategory.WORKING,
    ) -> KeyMetadata:
        if length not in (16, 24, 32):
            raise ValueError("SM4 key length must be 16, 24, or 32 bytes")

        key_id = self._new_key_id()
        now = self._now()
        metadata = KeyMetadata(
            key_id=key_id,
            label=label,
            category=category,
            algorithm=KeyAlgorithm.SM4,
            state=KeyState.ACTIVE,
            version=1,
            created_at=now,
            updated_at=now,
            usage=tuple(usage),
        )
        self._records[key_id] = _KeyRecord(
            metadata=metadata,
            secret_key=bytearray(self.device.generate_random(length)),
        )
        return metadata

    def create_hmac_key(
            self,
            label: str,
            length: int = 32,
            usage: Iterable[str] = ("hmac", "verify"),
            category: KeyCategory = KeyCategory.LOG_INTEGRITY,
    ) -> KeyMetadata:
        if length < 16:
            raise ValueError("HMAC key length must be at least 16 bytes")

        key_id = self._new_key_id()
        now = self._now()
        metadata = KeyMetadata(
            key_id=key_id,
            label=label,
            category=category,
            algorithm=KeyAlgorithm.SM3_HMAC,
            state=KeyState.ACTIVE,
            version=1,
            created_at=now,
            updated_at=now,
            usage=tuple(usage),
        )
        self._records[key_id] = _KeyRecord(
            metadata=metadata,
            secret_key=bytearray(self.device.generate_random(length)),
        )
        return metadata

    def create_device_signing_key(self, label: str = "device-signing") -> KeyMetadata:
        return self.create_sm2_key_pair(
            label=label,
            usage=("sign", "verify"),
            category=KeyCategory.DEVICE_SIGNING,
        )

    def create_device_encryption_key(self, label: str = "device-encryption") -> KeyMetadata:
        return self.create_sm2_key_pair(
            label=label,
            usage=("encrypt", "decrypt", "key_agreement"),
            category=KeyCategory.DEVICE_ENCRYPTION,
        )

    def create_working_key(self, label: str = "working") -> KeyMetadata:
        return self.create_sm4_key(
            label=label,
            usage=("encrypt", "decrypt", "integrity"),
            category=KeyCategory.WORKING,
        )

    def create_session_encryption_key(self, label: str = "ssh-session-encryption") -> KeyMetadata:
        return self.create_sm4_key(
            label=label,
            usage=("encrypt", "decrypt"),
            category=KeyCategory.SSH_SESSION_ENCRYPTION,
        )

    def create_session_integrity_key(self, label: str = "ssh-session-integrity") -> KeyMetadata:
        return self.create_hmac_key(
            label=label,
            usage=("hmac", "verify"),
            category=KeyCategory.SSH_SESSION_INTEGRITY,
        )

    def create_log_integrity_key(self, label: str = "log-integrity") -> KeyMetadata:
        return self.create_hmac_key(
            label=label,
            usage=("hmac", "verify"),
            category=KeyCategory.LOG_INTEGRITY,
        )

    def register_ukey_signing_key(self, label: str, public_key: bytes) -> KeyMetadata:
        return self._register_ukey_public_key(
            label=label,
            public_key=public_key,
            category=KeyCategory.IDENTITY_UKEY_SIGNING,
            usage=("verify", "identity_auth"),
        )

    def register_ukey_encryption_key(self, label: str, public_key: bytes) -> KeyMetadata:
        return self._register_ukey_public_key(
            label=label,
            public_key=public_key,
            category=KeyCategory.IDENTITY_UKEY_ENCRYPTION,
            usage=("encrypt", "key_wrap"),
        )

    def list_keys(self, state: Optional[KeyState] = None) -> list[KeyMetadata]:
        records = self._records.values()
        if state is not None:
            records = [record for record in records if record.metadata.state == state]
        return [record.metadata for record in records]

    def get_key(self, key_id: str) -> KeyMetadata:
        return self._get_record(key_id).metadata

    def disable_key(self, key_id: str) -> KeyMetadata:
        return self._set_state(key_id, KeyState.DISABLED)

    def enable_key(self, key_id: str) -> KeyMetadata:
        return self._set_state(key_id, KeyState.ACTIVE)

    def destroy_key(self, key_id: str) -> KeyMetadata:
        return self.zeroize_key(key_id)

    def zeroize_key(self, key_id: str, fill: int = 0x00) -> KeyMetadata:
        record = self._get_record(key_id)
        self._zeroize_record(record, fill=fill)
        return self._set_state(key_id, KeyState.DESTROYED)

    def zeroize_all(self, fill: int = 0x00) -> list[KeyMetadata]:
        return [
            self.zeroize_key(key_id, fill=fill)
            for key_id in list(self._records.keys())
        ]

    def rotate_sm4_key(self, key_id: str) -> KeyMetadata:
        record = self._get_record(key_id)
        self._require_algorithm(record, KeyAlgorithm.SM4)
        self._require_active(record)

        old_secret_key = record.secret_key
        record.secret_key = bytearray(self.device.generate_random(len(old_secret_key) or 16))
        zeroize_mutable_buffer(old_secret_key)
        record.metadata = self._replace_metadata(
            record.metadata,
            version=record.metadata.version + 1,
            updated_at=self._now(),
        )
        return record.metadata

    def export_public_key(self, key_id: str) -> str:
        record = self._get_record(key_id)
        self._require_algorithm(record, KeyAlgorithm.SM2)
        self._require_active(record)
        return base64.b64encode(record.public_key).decode("ascii")

    def encrypt_sm4(self, key_id: str, plain_text: bytes, alg_id: int = SGD_SM4_ECB) -> bytes:
        record = self._get_record(key_id)
        self._require_algorithm(record, KeyAlgorithm.SM4)
        self._require_active(record)

        session = self.device.new_session()
        try:
            return bytes(session.encrypt(plain_text, record.secret_key, alg_id))
        finally:
            session.close()

    def decrypt_sm4(self, key_id: str, cipher_text: bytes, alg_id: int = SGD_SM4_ECB) -> bytes:
        record = self._get_record(key_id)
        self._require_algorithm(record, KeyAlgorithm.SM4)
        self._require_active(record)

        session = self.device.new_session()
        try:
            return bytes(session.decrypt(cipher_text, record.secret_key, alg_id))
        finally:
            session.close()

    def compute_hmac(self, key_id: str, data: bytes) -> bytes:
        record = self._get_record(key_id)
        self._require_algorithm(record, KeyAlgorithm.SM3_HMAC)
        self._require_active(record)
        return self.device.sm3_hmac(record.secret_key, data)

    def generate_ukey_challenge(self, length: int = 32) -> bytes:
        if length < 16:
            raise ValueError("UKey challenge length must be at least 16 bytes")
        return self.device.generate_random(length)

    def verify_ukey_signature(self, key_id: str, raw_data: bytes, sign_data: bytes) -> bool:
        record = self._get_record(key_id)
        self._require_algorithm(record, KeyAlgorithm.SM2)
        self._require_category(record, KeyCategory.IDENTITY_UKEY_SIGNING)
        self._require_active(record)

        session = self.device.new_session()
        try:
            return session.verify_sign_ecc(
                SGD_SM2,
                bytes(record.public_key),
                raw_data,
                sign_data,
            )
        finally:
            session.close()

    def _get_record(self, key_id: str) -> _KeyRecord:
        record = self._records.get(key_id)
        if record is None:
            raise KeyError(f"Piico key not found: {key_id}")
        return record

    def _register_ukey_public_key(
            self,
            label: str,
            public_key: bytes,
            category: KeyCategory,
            usage: Iterable[str],
    ) -> KeyMetadata:
        if category not in (KeyCategory.IDENTITY_UKEY_SIGNING, KeyCategory.IDENTITY_UKEY_ENCRYPTION):
            raise ValueError("UKey key category is required")
        if not public_key:
            raise ValueError("UKey public key is required")

        key_id = self._new_key_id()
        now = self._now()
        metadata = KeyMetadata(
            key_id=key_id,
            label=label,
            category=category,
            algorithm=KeyAlgorithm.SM2,
            state=KeyState.ACTIVE,
            version=1,
            created_at=now,
            updated_at=now,
            usage=tuple(usage),
        )
        self._records[key_id] = _KeyRecord(
            metadata=metadata,
            public_key=bytearray(public_key),
        )
        return metadata

    def _set_state(self, key_id: str, state: KeyState) -> KeyMetadata:
        record = self._get_record(key_id)
        if record.metadata.state == KeyState.DESTROYED and state != KeyState.DESTROYED:
            raise ValueError(f"Destroyed key cannot be re-enabled: {key_id}")
        record.metadata = self._replace_metadata(
            record.metadata,
            state=state,
            updated_at=self._now(),
        )
        return record.metadata

    @staticmethod
    def _require_algorithm(record: _KeyRecord, algorithm: KeyAlgorithm) -> None:
        if record.metadata.algorithm != algorithm:
            raise ValueError(f"Key algorithm must be {algorithm.value}")

    @staticmethod
    def _require_category(record: _KeyRecord, category: KeyCategory) -> None:
        if record.metadata.category != category:
            raise ValueError(f"Key category must be {category.value}")

    @staticmethod
    def _require_active(record: _KeyRecord) -> None:
        if record.metadata.state != KeyState.ACTIVE:
            raise ValueError(f"Key is not active: {record.metadata.key_id}")

    @staticmethod
    def _zeroize_record(record: _KeyRecord, fill: int = 0x00) -> None:
        zeroize_mutable_buffer(record.public_key, fill=fill)
        zeroize_mutable_buffer(record.private_key, fill=fill)
        zeroize_mutable_buffer(record.secret_key, fill=fill)

    @staticmethod
    def _replace_metadata(metadata: KeyMetadata, **changes) -> KeyMetadata:
        values = {
            "key_id": metadata.key_id,
            "label": metadata.label,
            "category": metadata.category,
            "algorithm": metadata.algorithm,
            "state": metadata.state,
            "version": metadata.version,
            "created_at": metadata.created_at,
            "updated_at": metadata.updated_at,
            "usage": metadata.usage,
        }
        values.update(changes)
        return KeyMetadata(**values)

    @staticmethod
    def _new_key_id() -> str:
        return f"piico-key-{uuid.uuid4().hex}"

    @staticmethod
    def _now() -> datetime:
        return datetime.now(timezone.utc)
