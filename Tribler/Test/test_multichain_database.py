import unittest
import os

from Tribler.dispersy.crypto import ECCrypto

from Tribler.Test.test_multichain_utilities import TestBlock, MultiChainTestCase
from Tribler.community.multichain.database import MultiChainDB
from Tribler.community.multichain.database import DATABASE_DIRECTORY, DATABASE_PATH


class TestDatabase(MultiChainTestCase):
    """
    Tests the Database for MultiChain community.
    """

    def __init__(self, *args, **kwargs):
        super(TestDatabase, self).__init__(*args, **kwargs)

        self.public_key = "own_key"
        self.persistence = None

    def setUp(self, **kwargs):
        super(TestDatabase, self).setUp(**kwargs)
        path = os.path.join(self.getStateDir(), DATABASE_DIRECTORY)
        if not os.path.exists(path):
            os.makedirs(path)
        self.persistence = MultiChainDB(self.getStateDir())

    def tearDown(self, **kwargs):
        self.persistence.close()
        os.remove(os.path.join(self.getStateDir(), DATABASE_PATH))
        os.rmdir(os.path.join(self.getStateDir(), DATABASE_DIRECTORY))

    def test_add_block(self):
        # Arrange
        db = self.persistence
        block1 = TestBlock()
        # Act
        db.add_block(block1)
        # Assert
        result = db.get_by_block_id(block1.id)
        self.assertEqual_block(block1, result)

    def test_add_two_blocks(self):
        # Arrange
        db = self.persistence
        block1 = TestBlock()
        block2 = TestBlock()
        # Act
        db.add_block(block1)
        db.add_block(block2)
        # Assert
        result = db.get_by_block_id(block2.id)
        super(TestDatabase, self).assertEqual_block(block2, result)

    def test_add_block_valid_pk(self):
        # Arrange
        db = self.persistence
        block1 = TestBlock()
        # Act
        db.add_block(block1)
        pk_req = db.get_by_block_id(block1.id).public_key_requester
        pk_res = db.get_by_block_id(block1.id).public_key_responder
        # Assert
        crypto = ECCrypto()
        self.assertTrue(crypto.is_valid_public_bin(pk_req), "Invalid public binary for pk requester.")
        self.assertTrue(crypto.is_valid_public_bin(pk_res), "Invalid public binary for pk responder.")

    def test_get_block_non_existing(self):
        # Arrange
        db = self.persistence
        block1 = TestBlock()
        # Act
        result = db.get_by_block_id(block1.id)
        # Assert
        self.assertEqual(None, result)

    def test_contains_block_id_positive(self):
        # Arrange
        db = self.persistence
        block1 = TestBlock()
        db.add_block(block1)
        # Act & Assert
        self.assertTrue(db.contains(block1.id))

    def test_contains_block_id_negative(self):
        # Arrange
        db = self.persistence
        # Act & Assert
        self.assertFalse(db.contains("NON EXISTING ID"))

    def test_contains_signature_pk_positive(self):
        # Arrange
        db = self.persistence
        block1 = TestBlock()
        db.add_block(block1)
        # Act & Assert
        self.assertTrue(db.contains_signature(block1.signature_requester, block1.public_key_requester))

    def test_contains_signature_pk_false(self):
        # Arrange
        db = self.persistence
        block1 = TestBlock()
        # Act & Assert
        self.assertFalse(db.contains_signature(block1.signature_requester, block1.public_key_requester))

    def test_get_sequence_number_not_existing(self):
        # Arrange
        db = self.persistence
        # Act & Assert
        self.assertEquals(db.get_latest_sequence_number("NON EXISTING KEY"), -1)

    def test_get_sequence_number_public_key_requester(self):
        # Arrange
        # Make sure that there is a responder block with a lower sequence number.
        # To test that it will look for both responder and requester.
        db = self.persistence
        block1 = TestBlock()
        db.add_block(block1)
        block2 = TestBlock()
        block2.public_key_responder = block1.public_key_requester
        block2.sequence_number_responder = block1.sequence_number_requester-5
        db.add_block(block2)
        # Act & Assert
        self.assertEquals(db.get_latest_sequence_number(block1.public_key_requester), block1.sequence_number_requester)

    def test_get_sequence_number_public_key_responder(self):
        # Arrange
        # Make sure that there is a requester block with a lower sequence number.
        # To test that it will look for both responder and requester.
        db = self.persistence
        block1 = TestBlock()
        db.add_block(block1)
        block2 = TestBlock()
        block2.public_key_requester = block1.public_key_responder
        block2.sequence_number_requester = block1.sequence_number_responder-5
        db.add_block(block2)
        # Act & Assert
        self.assertEquals(db.get_latest_sequence_number(block1.public_key_responder), block1.sequence_number_responder)

    def test_get_previous_id_not_existing(self):
        # Arrange
        db = self.persistence
        # Act & Assert
        self.assertEquals(db.get_previous_id("NON EXISTING KEY"), None)

    def test_get_previous_id_public_key_requester(self):
        # Arrange
        # Make sure that there is a responder block with a lower sequence number.
        # To test that it will look for both responder and requester.
        db = self.persistence
        block1 = TestBlock()
        db.add_block(block1)
        block2 = TestBlock()
        block2.public_key_responder = block1.public_key_requester
        block2.sequence_number_responder = block1.sequence_number_requester-5
        db.add_block(block2)
        # Act & Assert
        self.assertEquals(db.get_previous_id(block1.public_key_requester), block1.id)

    def test_get_previous_id_public_key_responder(self):
        # Arrange
        # Make sure that there is a requester block with a lower sequence number.
        # To test that it will look for both responder and requester.
        db = self.persistence
        block1 = TestBlock()
        db.add_block(block1)
        block2 = TestBlock()
        block2.public_key_requester = block1.public_key_responder
        block2.sequence_number_requester = block1.sequence_number_responder-5
        db.add_block(block2)
        # Act & Assert
        self.assertEquals(db.get_previous_id(block1.public_key_responder), block1.id)

    def test_get_total(self):
        # Arrange
        db = self.persistence
        block1 = TestBlock()
        block2 = TestBlock()
        block2.public_key_requester = block1.public_key_responder
        block2.sequence_number_requester = block1.sequence_number_responder + 5
        block2.total_up_requester = block1.total_up_responder + block2.up
        block2.total_down_requester = block1.total_down_responder + block2.down
        db.add_block(block1)
        db.add_block(block2)
        # Act
        (result_up, result_down) = db.get_total(block2.public_key_requester)
        # Assert
        self.assertEqual(block2.total_up_requester, result_up)
        self.assertEqual(block2.total_down_requester, result_down)

    def test_get_total_not_existing(self):
        # Arrange
        db = self.persistence
        block1 = TestBlock()
        # Act
        (result_up, result_down) = db.get_total(block1.public_key_requester)
        # Assert
        self.assertEqual(-1, result_up)
        self.assertEqual(-1, result_down)

if __name__ == '__main__':
    unittest.main()