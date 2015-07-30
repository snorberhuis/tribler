import logging
from hashlib import sha1
from struct import unpack

from Tribler.Test.test_multichain_utilities import TestBlock, MultiChainTestCase
from Tribler.community.multichain.conversion import MultiChainConversion, split_function, signature_format, append_format

from Tribler.community.multichain.community import SIGNATURE
from Tribler.community.multichain.payload import SignaturePayload, EMPTY_HASH

from Tribler.dispersy.community import Community
from Tribler.dispersy.authentication import NoAuthentication
from Tribler.dispersy.resolution import PublicResolution
from Tribler.dispersy.distribution import DirectDistribution
from Tribler.dispersy.destination import CandidateDestination
from Tribler.dispersy.message import Message
from Tribler.dispersy.conversion import DefaultConversion
from Tribler.dispersy.crypto import ECCrypto


class TestConversion(MultiChainTestCase):

    def __init__(self, *args, **kwargs):
        super(TestConversion, self).__init__(*args, **kwargs)
        self.community = TestCommunity()

    def test_encoding_decoding_signature(self):
        # Arrange
        converter = MultiChainConversion(self.community)

        meta = self.community.get_meta_message(SIGNATURE)
        block = TestBlock()

        message = meta.impl(distribution=(self.community.claim_global_time(),),
                            payload=tuple(block.generate_signature_payload()))
        # Act
        encoded_message = converter._encode_signature(message)[0]

        result = converter._decode_signature(TestPlaceholder(meta), 0, encoded_message)[1]
        # Assert
        self.assertEqual_signature_payload(block, result)

    def test_encoding_decoding_signature_requester(self):
        # Arrange
        converter = MultiChainConversion(self.community)

        meta = self.community.get_meta_message(SIGNATURE)
        block = TestBlock()

        message = meta.impl(distribution=(self.community.claim_global_time(),),
                            payload=tuple(block.generate_requester()))
        # Act
        encoded_message = converter._encode_signature(message)[0]

        result = converter._decode_signature(TestPlaceholder(meta), 0, encoded_message)[1]
        # Assert
        self.assertEqual_signature_request(block, result)
        self.assertEqual(-1, result.total_up_responder)
        self.assertEqual(-1, result.total_down_responder)
        self.assertEqual(-1, result.sequence_number_responder)
        self.assertEqual(EMPTY_HASH, result.previous_hash_responder)

    def test_split_function(self):
        # Arrange
        converter = MultiChainConversion(self.community)

        meta = self.community.get_meta_message(SIGNATURE)
        block = TestBlock()

        message = meta.impl(distribution=(self.community.claim_global_time(),),
                            payload=tuple(block.generate_signature_payload()))
        # Act
        encoded_message = converter._encode_signature(message)[0]
        result = split_function(encoded_message)
        # Assert
        values = unpack(signature_format[:-len(append_format)], result[0])
        self.assertEqual(6, len(values))
        self.assertEqual(block.up, values[0])
        self.assertEqual(block.down, values[1])
        self.assertEqual(block.total_up_requester, values[2])
        self.assertEqual(block.total_down_requester, values[3])
        self.assertEqual(block.sequence_number_requester, values[4])
        self.assertEqual(block.previous_hash_requester, values[5])

        self.assertEqual(encoded_message, result[1])


class TestPlaceholder:

    def __init__(self, meta):
        self.meta = meta


# noinspection PyMissingConstructor
class TestCommunity(Community):

    crypto = ECCrypto()

    def __init__(self):
        self.key = self.crypto.generate_key(u"very-low")
        self.pk = self.crypto.key_to_bin(self.key.pub())

        self.meta_message_cache = {}

        self._cid = sha1(self.pk).digest()
        self._meta_messages = {}
        self._initialize_meta_messages()

        self._global_time = 0
        self._do_pruning = False
        self._logger = logging.getLogger(self.__class__.__name__)

        self._conversions = self.initiate_conversions()

    def initiate_meta_messages(self):
        return super(TestCommunity, self).initiate_meta_messages() + [
            Message(self, SIGNATURE,
                    NoAuthentication(),
                    PublicResolution(),
                    DirectDistribution(),
                    CandidateDestination(),
                    SignaturePayload(),
                    self._not_implemented,
                    self._not_implemented)]

    @staticmethod
    def _not_implemented(self):
        return

    def initiate_conversions(self):
        return [DefaultConversion(self), MultiChainConversion(self)]