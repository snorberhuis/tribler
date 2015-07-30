"""
File containing utilities used in testing the double entry community.
"""

import random

from hashlib import sha1

from Tribler.dispersy.crypto import ECCrypto

from Tribler.Test.test_as_server import AbstractServer


class TestBlock:
    """
    Test Block that simulates a block message used in MultiChain.
    Also used in other test files for MultiChain.
    """

    def __init__(self):
        crypto = ECCrypto()
        key_requester = crypto.generate_key(u"very-low")
        key_responder = crypto.generate_key(u"very-low")

        # Random payload but unique numbers.
        self.sequence_number_requester = random.randint(50, 100)
        self.sequence_number_responder = random.randint(101, 200)
        self.up = random.randint(201, 220)
        self.down = random.randint(221, 240)
        self.total_up = random.randint(241, 260)
        self.total_down = random.randint(261, 280)
        self.request_identifier = random.randint(281, 300)

        # A random hash is generated for the previous hash. It is only used to test if a hash can be persisted.
        self.previous_hash_requester = sha1(str(random.randint(0, 100000))).digest()
        self.public_key_requester = crypto.key_to_bin(key_requester.pub())
        self.signature_requester = crypto.create_signature(key_requester, encode_signing_format(
            self._generate_signature_requester()))

        # A random hash is generated for the previous hash. It is only used to test if a hash can be persisted.
        self.previous_hash_responder = sha1(str(random.randint(100001, 200000))).digest()
        self.public_key_responder = crypto.key_to_bin(key_responder.pub())
        self.signature_responder = crypto.create_signature(key_responder, encode_signing_format(
            self._generate_signature_responder()))

    @property
    def id(self):
        return self.generate_hash()

    def _generate_signature_requester(self):
        return [self.request_identifier, self.up, self.down, self.total_up, self.total_down,
                self.sequence_number_requester,
                self.previous_hash_requester, self.public_key_requester]

    def generate_signature(self):
        return [self.up, self.down, self.total_up, self.total_down,
                self.sequence_number_requester, self.previous_hash_requester,
                self.sequence_number_responder, self.previous_hash_responder]

    def generate_signature_request(self):
        return self._generate_signature_requester() + [self.signature_requester]

    def _generate_signature_responder(self):
        return self.generate_signature_request() + [self.sequence_number_responder, self.previous_hash_responder,
                                                    self.public_key_responder]

    def generate_signature_response(self):
        return self._generate_signature_responder() + [self.signature_responder]

    def generate_hash(self):
        # This block uses a different way of generating the hash.
        data = encode_signing_format(self.generate_signature_response()[1:])
        return sha1(data).digest()


class MultiChainTestCase(AbstractServer):
    def __init__(self, *args, **kwargs):
        super(MultiChainTestCase, self).__init__(*args, **kwargs)

    def assertEqual_block(self, expected_block, actual_block):
        """
        Function to assertEqual two blocks
        :param expected_block: Expected result block
        :param actual_block: Actual result block
        """
        self._assertEqual_payload(expected_block, actual_block)
        self._assertEqual_RequesterPart(expected_block, actual_block)
        self._assertEqual_ResponderPart(expected_block, actual_block)

    def assertEqual_request(self, expected_block, actual_block):
        """
        Function to assertEqual two requests
        :param expected_block: Expected result request
        :param actual_block: Actual result request
        """
        self.assertEqual(expected_block.request_identifier, actual_block.request_identifier)
        self._assertEqual_payload(expected_block, actual_block)
        self._assertEqual_RequesterPart(expected_block, actual_block)

    def assertEqual_signature(self, expected_block, actual_block):
        self._assertEqual_payload(expected_block, actual_block)
        self.assertEqual(expected_block.sequence_number_requester, actual_block.sequence_number_requester)
        self.assertEqual(expected_block.previous_hash_requester, actual_block.previous_hash_requester)
        self.assertEqual(expected_block.sequence_number_responder, actual_block.sequence_number_responder)
        self.assertEqual(expected_block.previous_hash_responder, actual_block.previous_hash_responder)

    def _assertEqual_payload(self, expected_block, actual_block):
        self.assertEqual(expected_block.up, actual_block.up)
        self.assertEqual(expected_block.down, actual_block.down)
        self.assertEqual(expected_block.total_up, actual_block.total_up)
        self.assertEqual(expected_block.total_down, actual_block.total_down)

    def _assertEqual_RequesterPart(self, expected_block, actual_block):
        self.assertEqual(expected_block.sequence_number_requester, actual_block.sequence_number_requester)
        self.assertEqual(expected_block.previous_hash_requester, actual_block.previous_hash_requester)
        self.assertEqual(expected_block.signature_requester, actual_block.signature_requester)
        self.assertEqual(expected_block.public_key_requester, actual_block.public_key_requester)

    def _assertEqual_ResponderPart(self, expected_block, actual_block):
        self.assertEqual(expected_block.sequence_number_responder, actual_block.sequence_number_responder)
        self.assertEqual(expected_block.previous_hash_responder, actual_block.previous_hash_responder)
        self.assertEqual(expected_block.signature_responder, actual_block.signature_responder)
        self.assertEqual(expected_block.public_key_responder, actual_block.public_key_responder)


def encode_signing_format(data):
    """
    Prepare a iterable for singing.
    :param data: Iterable with objects transformable to string
    :return: string to be signed containing the data.
    """
    return ".".join(map(str, data))