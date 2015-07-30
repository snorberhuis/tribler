"""
File containing the MultiChain Community
"""

import logging
import base64
from hashlib import sha1
from Queue import Queue
from threading import Lock

from Tribler.dispersy.authentication import DoubleMemberAuthentication
from Tribler.dispersy.resolution import PublicResolution
from Tribler.dispersy.distribution import DirectDistribution
from Tribler.dispersy.destination import CandidateDestination
from Tribler.dispersy.community import Community
from Tribler.dispersy.message import Message
from Tribler.dispersy.crypto import ECCrypto
from Tribler.dispersy.conversion import DefaultConversion

from Tribler.community.multichain.payload import SignaturePayload
from Tribler.community.multichain.database import MultiChainDB, DatabaseBlock
from Tribler.community.multichain.conversion import MultiChainConversion, split_function

SIGNATURE = u"signature"

""" ID of the first block of the chain. """
GENESIS_ID = sha1("GENESIS_ID").digest()


class MultiChainCommunity(Community):
    """
    Community for reputation based on MultiChain tamper proof interaction history.
    """

    def __init__(self, *args, **kwargs):
        super(MultiChainCommunity, self).__init__(*args, **kwargs)
        self._logger = logging.getLogger(self.__class__.__name__)

        self._ec = self.my_member.private_key
        self._public_key = ECCrypto().key_to_bin(self._ec.pub())
        self.persistence = MultiChainDB(self.dispersy.working_directory)

        # Queue that holds incoming requests to be processed after a outgoing request has been answered.
        self._incoming_request_queue = Queue()
        # Lock for operations on the chain
        self.chain_lock = Lock()
        # Lock for the timeout of a signature request
        self.request_timeout_lock = Lock()
        # No response is expected yet.
        self.expected_response = None

    def initialize(self, a=None, b=None):
        super(MultiChainCommunity, self).initialize()

    @classmethod
    def get_master_members(cls, dispersy):
        # generated: Wed Dec  3 10:31:16 2014
        # curve: NID_sect571r1
        # len: 571 bits ~ 144 bytes signature
        # pub: 170  3081a7301006072a8648ce3d020106052b810400270381920004059f45b75d63f865e3c7b350bd3ccdc99dbfbf76f
        # dfb524939f070223c3ea9ea5d0536721cf9afbbec5693798e289b964fefc930961dfe1a7f71c445031434aba637bb9
        # 3b947fb81603f649d4a08e5698e677059b9d3a441986c16f8da94d4aa2afbf10fe056cd65741108fe6a880606869c
        #           a81fdcb2db302ac15905d6e75f96b39ccdaf068bdbbda81a6356f53f7ce4e
        # pub-sha1 f66a50b35c4a0d45abd0052f574c5ecc233b8e54
        # -----BEGIN PUBLIC KEY-----
        # MIGnMBAGByqGSM49AgEGBSuBBAAnA4GSAAQFn0W3XWP4ZePHs1C9PM3Jnb+/dv37
        # Ukk58HAiM+qepdBTZyHPmvu+xWk3mOKJuWT+/JMJYd/hp/ccRFAxQ0q6Y3u5O5R/
        # uBYD9knUoI5WmOZ3BZudOkQZhsFvjalNSqKvvxD+BWzWV0EQj+aogGBoacqB/cst
        # swKsFZBdbnX5aznM2vBovbvagaY1b1P3zk4=
        # -----END PUBLIC KEY-----
        master_key = "3081a7301006072a8648ce3d020106052b810400270381920004059f45b75d63f865e3c7b350bd3ccdc99dbfbf76f" + \
                     "dfb524939f0702233ea9ea5d0536721cf9afbbec5693798e289b964fefc930961dfe1a7f71c445031434aba637bb9" + \
                     "3b947fb81603f649d4a08e5698e677059b9d3a441986c16f8da94d4aa2afbf10fe056cd65741108fe6a880606869c" + \
                     "a81fdcb2db302ac15905d6e75f96b39ccdaf068bdbbda81a6356f53f7ce4e"
        master_key_hex = master_key.decode("HEX")
        master = dispersy.get_member(public_key=master_key_hex)
        return [master]

    def initiate_meta_messages(self):
        return super(MultiChainCommunity, self).initiate_meta_messages() + [
            Message(self, SIGNATURE,
                    DoubleMemberAuthentication(
                        allow_signature_func=self.allow_signature_request, split_payload_func=split_function),
                    PublicResolution(),
                    DirectDistribution(),
                    CandidateDestination(),
                    SignaturePayload(),
                    self._generic_timeline_check,
                    self.received_signature_response)]

    def initiate_conversions(self):
        return [DefaultConversion(self), MultiChainConversion(self)]

    def publish_signature_request_message(self, candidate):
        """
        Creates and sends out a signed signature_request message.
        """
        self._logger.info("Sending signature request.")
        # The lock is lifted after the timeout or a valid signature response is received.
        self._logger.info("Get Lock: send signature request: %s" % self.chain_lock.locked())
        self.chain_lock.acquire()
        self._logger.info("Acquired Lock: send signature request.")

        message = self.create_signature_request_message(candidate)
        self.create_signature_request(candidate, message, self.allow_signature_response, timeout=5.0)

    def create_signature_request_message(self, candidate):
        """
        Create a signature request message using the current time stamp.
        :return: Signature_request message ready for distribution.
        """
        # Instantiate the data
        up = 1
        down = 2
        total_up = 3
        total_down = 4
        # Instantiate the personal information
        sequence_number_requester = self._get_next_sequence_number()
        previous_hash_requester = self._get_latest_hash()

        payload = (up, down, total_up, total_down, sequence_number_requester, previous_hash_requester)
        meta = self.get_meta_message(SIGNATURE)

        message = meta.impl(authentication=([self.my_member, candidate.get_member()],),
                            distribution=(self.claim_global_time(),),
                            payload=payload)
        return message

    def allow_signature_request(self, message):
        """
        We've received a signature request message, we must either:
            a. append to this message our data (Afterwards we sign the message.).
            b. None (if we want to drop this message)
        """
        self._logger.info("Received signature request.")
        self._logger.info("Chain Lock: process request: %s" % self.chain_lock.locked())
        if self.chain_lock.acquire(False):
            self._logger.info("Chain Lock: acquired to process request.")
            # TODO: This code always signs a request. Checks and rejects should be inserted here!
            payload = message.payload

            total_up_responder = 1
            total_down_responder = 1
            sequence_number_responder = self._get_next_sequence_number()
            previous_hash_responder = self._get_latest_hash()

            payload = (payload.up, payload.down, payload.total_up_requester, payload.total_down_requester,
                       payload.sequence_number_requester, payload.previous_hash_requester,
                       total_up_responder, total_down_responder,
                       sequence_number_responder, previous_hash_responder)

            meta = self.get_meta_message(SIGNATURE)

            message = meta.impl(authentication=(message.authentication.members, message.authentication.signatures),
                                distribution=(message.distribution.global_time,),
                                payload=payload)
            self.persist_signature_response(message)
            self.chain_lock.release()
            self._logger.info("Sending signature response.")
            return message
        else:
            self._logger.info("Chain Lock: not acquired. Dropping request.")
            return None

    def allow_signature_response(self, request, response, modified):
        """
        We've received a signature response message after sending a request, we must return either:
            a. True, if we accept this message
            b. False, if not (because of inconsistencies in the payload)
        """
        if not response:
            self._logger.info("Release lock: Timeout received")
            self.chain_lock.release()
            return False
        else:
            self._logger.info("Signature response received. Modified: %s" % modified)
            return request.payload.sequence_number_requester == response.payload.sequence_number_requester and \
                request.payload.previous_hash_requester == response.payload.previous_hash_requester and \
                modified

    def received_signature_response(self, messages):
        """
        We've received a valid signature response and must process this message.
        """
        self._logger.info("Valid %s signature responses received." % len(messages))
        for message in messages:
            if self.request_timeout_lock.acquire(False):

                # TODO: Check expecting response
                self.persist_signature_response(message)
                # Release lock
                self._logger.info("Release lock: received signature response.")
                self.chain_lock.release()
                self.request_timeout_lock.release()

    def persist_signature_response(self, message):
        """
        Persist the signature response message.
        A hash will be created from the message and this will be used as an unique identifier.
        :param message:
        """
        block = DatabaseBlock.from_message(message)
        # Create the hash of the message
        block_hash = sha1(message.packet).digest()
        self._logger.info("Persisting sr: %s" % base64.encodestring(block_hash))
        self.persistence.add_block(block_hash, block)

    def get_key(self):
        return self._ec

    def _get_next_sequence_number(self):
        return self.persistence.get_latest_sequence_number(self._public_key) + 1

    def _get_latest_hash(self):
        previous_hash = self.persistence.get_previous_id(self._public_key)
        return previous_hash if previous_hash else GENESIS_ID

    def unload_community(self):
        self._logger.debug("Unloading the MultiChain Community.")
        super(MultiChainCommunity, self).unload_community()
        # Close the persistence layer
        self.persistence.close()