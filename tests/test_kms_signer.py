import os

import boto3
import pytest
from moto import mock_aws

from polonity_ethereum_kms_signer.kms import get_eth_address, sign_transaction

try:
    # web3 が入っていれば使う。なければスキップ
    from web3 import Web3
except ImportError:  # pragma: no cover
    Web3 = None


@pytest.fixture
def kms_client():
    # moto の AWS はリージョン指定しておくとハマりづらい
    with mock_aws():
        client = boto3.client("kms", region_name="ap-northeast-1")
        yield client


@pytest.fixture
def kms_key_id(kms_client):
    # ライブラリが想定している KMS キーのスペックに合わせる
    resp = kms_client.create_key(
        Description="test eth kms key",
        KeyUsage="SIGN_VERIFY",
        CustomerMasterKeySpec="ECC_SECG_P256K1",
    )
    return resp["KeyMetadata"]["KeyId"]


def test_get_eth_address_returns_checksum(kms_client, kms_key_id):
    # 実装側が (key_id, kms_client) を受ける想定
    addr = get_eth_address(kms_key_id, kms_client)

    assert isinstance(addr, str)
    assert addr.startswith("0x")
    assert len(addr) == 42  # 0x + 40 hex

    # web3 があれば checksum まで確認
    if Web3 is not None:
        assert addr == Web3.to_checksum_address(addr)


@pytest.mark.skipif(Web3 is None, reason="web3.py is required for signing test")
def test_sign_transaction_with_kms(kms_client, kms_key_id):
    # 送金トランザクションっぽい最小構成
    tx = {
        "nonce": 0,
        "to": Web3.to_checksum_address("0x" + "1" * 40),
        "value": 12345,
        "gas": 21000,
        "gasPrice": Web3.to_wei(1, "gwei"),
        # mainnet想定。ここは適宜変えてOK
        "chainId": 1,
    }

    # ライブラリが (tx, key_id, kms_client) を受けるようにしておくとテストしやすい
    signed = sign_transaction(tx, kms_key_id, kms_client)

    # README では `signed_tx.rawTransaction` を送っていたのでそれに倣う
    # https://github.com/meetmangukiya/ethereum-kms-signer
    raw = getattr(signed, "rawTransaction", None)
    assert raw is not None, "sign_transaction() は SignedTransaction 相当を返す想定です"
    assert isinstance(raw, (bytes, bytearray))
    assert len(raw) > 0
