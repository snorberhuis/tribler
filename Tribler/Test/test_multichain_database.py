import unittest
import os

from Tribler.dispersy.crypto import ECCrypto
from Tribler.dispersy.util import blocking_call_on_reactor_thread

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

    def setUpPreSession(self):
        super(TestDatabase, self).setUpPreSession()
        self.config.set_dispersy(True)

    def setUp(self, **kwargs):
        super(TestDatabase, self).setUp(**kwargs)
        path = os.path.join(self.getStateDir(), DATABASE_DIRECTORY)
        if not os.path.exists(path):
            os.makedirs(path)

    def tearDown(self, **kwargs):
        super(TestDatabase, self).tearDown()

    def addMembersToDispersy(self, dispersy, block):
        dispersy.get_member(public_key=block.public_key_requester)
        dispersy.get_member(public_key=block.public_key_responder)

    def getNewAddedBlock(self, db, dispersy):
        block = TestBlock()
        db.add_block(block)
        self.addMembersToDispersy(dispersy, block)
        return block

    def test_add_block(self):
        @blocking_call_on_reactor_thread
        def start():
            # Arrange
            dispersy = self.session.get_dispersy_instance()
            db = MultiChainDB(dispersy, self.getStateDir())
            block1 = TestBlock()
            self.addMembersToDispersy(dispersy, block1)
            # Act
            db.add_block(block1)
            # Assert
            result = db.get_by_block_id(block1.id)
            self.assertEqual_database_block(block1, result)
        self.startTest(start)

    def test_add_two_blocks(self):
        @blocking_call_on_reactor_thread
        def start():
            # Arrange
            dispersy = self.session.get_dispersy_instance()
            db = MultiChainDB(dispersy, self.getStateDir())
            block1 = TestBlock()
            self.addMembersToDispersy(dispersy, block1)
            block2 = TestBlock()
            self.addMembersToDispersy(dispersy, block2)
            # Act
            db.add_block(block1)
            db.add_block(block2)
            # Assert
            result = db.get_by_block_id(block2.id)
            self.assertEqual_database_block(block2, result)
        self.startTest(start)

    def test_add_block_valid_pk(self):
        @blocking_call_on_reactor_thread
        def start():
            # Arrange
            dispersy = self.session.get_dispersy_instance()
            db = MultiChainDB(dispersy, self.getStateDir())
            block1 = self.getNewAddedBlock(db, dispersy)
            # Act
            pk_req = db.get_by_block_id(block1.id).public_key_requester
            pk_res = db.get_by_block_id(block1.id).public_key_responder
            # Assert
            crypto = ECCrypto()
            self.assertTrue(crypto.is_valid_public_bin(pk_req), "Invalid public binary for pk requester.")
            self.assertTrue(crypto.is_valid_public_bin(pk_res), "Invalid public binary for pk responder.")
        self.startTest(start)

    def test_get_block_non_existing(self):
        @blocking_call_on_reactor_thread
        def start():
            # Arrange
            dispersy = self.session.get_dispersy_instance()
            db = MultiChainDB(dispersy, self.getStateDir())
            block1 = TestBlock()
            # Act
            result = db.get_by_block_id(block1.id)
            # Assert
            self.assertEqual(None, result)
        self.startTest(start)

    def test_contains_block_id_positive(self):
        @blocking_call_on_reactor_thread
        def start():
            # Arrange
            dispersy = self.session.get_dispersy_instance()
            db = MultiChainDB(dispersy, self.getStateDir())
            block1 = self.getNewAddedBlock(db, dispersy)
            # Act & Assert
            self.assertTrue(db.contains(block1.id))
        self.startTest(start)

    def test_contains_block_id_negative(self):
        @blocking_call_on_reactor_thread
        def start():
            # Arrange
            dispersy = self.session.get_dispersy_instance()
            db = MultiChainDB(dispersy, self.getStateDir())
            # Act & Assert
            self.assertFalse(db.contains("NON EXISTING ID"))
        self.startTest(start)

    def test_get_latest_sequence_number_not_existing(self):
        @blocking_call_on_reactor_thread
        def start():
            # Arrange
            dispersy = self.session.get_dispersy_instance()
            db = MultiChainDB(dispersy, self.getStateDir())
            # Act & Assert
            self.assertEquals(db.get_latest_sequence_number("NON EXISTING KEY"), -1)
        self.startTest(start)

    def test_get_latest_sequence_number_mid_requester(self):
        @blocking_call_on_reactor_thread
        def start():
            # Arrange
            # Make sure that there is a responder block with a lower sequence number.
            # To test that it will look for both responder and requester.
            dispersy = self.session.get_dispersy_instance()
            db = MultiChainDB(dispersy, self.getStateDir())
            block1 = self.getNewAddedBlock(db, dispersy)
            block2 = TestBlock()
            block2.public_key_responder = block1.public_key_requester
            block2.sequence_number_responder = block1.sequence_number_requester-5
            db.add_block(block2)
            self.addMembersToDispersy(dispersy, block2)
            # Act & Assert
            self.assertEquals(db.get_latest_sequence_number(block1.mid_requester),
                              block1.sequence_number_requester)
        self.startTest(start)

    def test_get_latest_sequence_number_mid_responder(self):
        @blocking_call_on_reactor_thread
        def start():
            # Arrange
            # Make sure that there is a requester block with a lower sequence number.
            # To test that it will look for both responder and requester.
            dispersy = self.session.get_dispersy_instance()
            db = MultiChainDB(dispersy, self.getStateDir())
            block1 = self.getNewAddedBlock(db, dispersy)
            block2 = TestBlock()
            block2.public_key_requester = block1.public_key_responder
            block2.sequence_number_requester = block1.sequence_number_responder-5
            db.add_block(block2)
            # Act & Assert
            self.assertEquals(db.get_latest_sequence_number(block1.mid_responder),
                              block1.sequence_number_responder)
        self.startTest(start)

    def test_get_previous_id_not_existing(self):
        @blocking_call_on_reactor_thread
        def start():
            # Arrange
            dispersy = self.session.get_dispersy_instance()
            db = MultiChainDB(dispersy, self.getStateDir())
            # Act & Assert
            self.assertEquals(db.get_previous_id("NON EXISTING KEY"), None)
        self.startTest(start)

    def test_get_previous_id_mid_requester(self):
        @blocking_call_on_reactor_thread
        def start():
            # Arrange
            # Make sure that there is a responder block with a lower sequence number.
            # To test that it will look for both responder and requester.
            dispersy = self.session.get_dispersy_instance()
            db = MultiChainDB(dispersy, self.getStateDir())
            block1 = self.getNewAddedBlock(db, dispersy)
            block2 = TestBlock()
            block2.public_key_responder = block1.public_key_requester
            block2.mid_responder = block1.mid_requester
            block2.sequence_number_responder = block1.sequence_number_requester-5
            db.add_block(block2)
            self.addMembersToDispersy(dispersy, block2)
            # Act & Assert
            self.assertEquals(db.get_previous_id(block1.mid_requester), block1.id)
        self.startTest(start)

    def test_get_previous_id_mid_responder(self):
        @blocking_call_on_reactor_thread
        def start():
            # Arrange
            # Make sure that there is a requester block with a lower sequence number.
            # To test that it will look for both responder and requester.
            dispersy = self.session.get_dispersy_instance()
            db = MultiChainDB(dispersy, self.getStateDir())
            block1 = self.getNewAddedBlock(db, dispersy)
            block2 = TestBlock()
            block2.public_key_requester = block1.public_key_responder
            block2.mid_requester = block1.mid_responder
            block2.sequence_number_requester = block1.sequence_number_responder-5
            db.add_block(block2)
            self.addMembersToDispersy(dispersy, block2)
            # Act & Assert
            self.assertEquals(db.get_previous_id(block1.mid_responder), block1.id)
        self.startTest(start)

    def test_get_by_sequence_number_by_mid_not_existing(self):
        @blocking_call_on_reactor_thread
        def start():
            # Arrange
            dispersy = self.session.get_dispersy_instance()
            db = MultiChainDB(dispersy, self.getStateDir())
            # Act & Assert
            self.assertEquals(db.get_by_sequence_number_and_mid(0, "NON EXISTING KEY"), None)
        self.startTest(start)

    def test_get_by_sequence_number_by_mid_requester(self):
        @blocking_call_on_reactor_thread
        def start():
            # Arrange
            # Make sure that there is a responder block with a lower sequence number.
            # To test that it will look for both responder and requester.
            dispersy = self.session.get_dispersy_instance()
            db = MultiChainDB(dispersy, self.getStateDir())
            block1 = self.getNewAddedBlock(db, dispersy)
            # Act & Assert
            self.assertEqual_database_block(block1, db.get_by_sequence_number_and_mid(
                block1.sequence_number_requester, block1.mid_requester))
        self.startTest(start)

    def test_get_by_sequence_number_by_mid_responder(self):
        @blocking_call_on_reactor_thread
        def start():
            # Arrange
            # Make sure that there is a responder block with a lower sequence number.
            # To test that it will look for both responder and requester.
            dispersy = self.session.get_dispersy_instance()
            db = MultiChainDB(dispersy, self.getStateDir())
            block1 = self.getNewAddedBlock(db, dispersy)
            # Act & Assert
            self.assertEqual_database_block(block1, db.get_by_sequence_number_and_mid(
                block1.sequence_number_responder, block1.mid_responder))
        self.startTest(start)

    def test_get_total(self):
        @blocking_call_on_reactor_thread
        def start():
            # Arrange
            dispersy = self.session.get_dispersy_instance()
            db = MultiChainDB(dispersy, self.getStateDir())
            block1 = self.getNewAddedBlock(db, dispersy)
            block2 = TestBlock()
            block2.public_key_requester = block1.public_key_responder
            block2.mid_requester = block1.mid_responder
            block2.sequence_number_requester = block1.sequence_number_responder + 5
            block2.total_up_requester = block1.total_up_responder + block2.up
            block2.total_down_requester = block1.total_down_responder + block2.down
            db.add_block(block2)
            self.addMembersToDispersy(dispersy, block2)
            # Act
            (result_up, result_down) = db.get_total(block2.mid_requester)
            # Assert
            self.assertEqual(block2.total_up_requester, result_up)
            self.assertEqual(block2.total_down_requester, result_down)
        self.startTest(start)

    def test_get_total_not_existing(self):
        @blocking_call_on_reactor_thread
        def start():
            # Arrange
            dispersy = self.session.get_dispersy_instance()
            db = MultiChainDB(dispersy, self.getStateDir())
            block1 = TestBlock()
            # Act
            (result_up, result_down) = db.get_total(block1.mid_requester)
            # Assert
            self.assertEqual(-1, result_up)
            self.assertEqual(-1, result_down)
        self.startTest(start)

    def test_get_total_half_signed(self):
        """
        Half signed records should not be counted in the total.
        """
        @blocking_call_on_reactor_thread
        def start():
            # Arrange
            dispersy = self.session.get_dispersy_instance()
            db = MultiChainDB(dispersy, self.getStateDir())
            block1 = self.getNewAddedBlock(db, dispersy)
            block2 = TestBlock()
            half_signed_block = TestBlock.half_signed()

            block2.public_key_requester = half_signed_block.public_key_requester = block1.public_key_responder
            block2.mid_requester = half_signed_block.mid_requester = block1.mid_responder

            half_signed_block.sequence_number_requester = block1.sequence_number_responder + 1
            block2.sequence_number_requester = half_signed_block.sequence_number_requester + 1

            half_signed_block.total_up_requester = block1.total_up_responder + half_signed_block.up
            half_signed_block.total_down_requester = block1.total_down_responder + half_signed_block.down

            block2.total_up_requester = block1.total_up_responder + block2.up
            block2.total_down_requester = block1.total_down_responder + block2.down

            db.add_block(half_signed_block)
            self.addMembersToDispersy(dispersy, half_signed_block)
            db.add_block(block2)
            self.addMembersToDispersy(dispersy, block2)
            # Act
            (result_up, result_down) = db.get_total(block2.mid_requester)
            # Assert
            self.assertEqual(block2.total_up_requester, result_up)
            self.assertEqual(block2.total_down_requester, result_down)
        self.startTest(start)

if __name__ == '__main__':
    unittest.main()