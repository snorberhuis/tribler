"""
File containing the MultiChain Community.
The MultiChain Community is the first step in an incremental approach in building a new reputation system.
This reputation system builds a tamper proof interaction history contained in a chain data-structure.
Every node has a chain and these chains intertwine by blocks shared by chains.
Full documentation will be available at http://repository.tudelft.nl/.
"""

import logging
import base64
from threading import Lock
from sqlite3 import IntegrityError

from Tribler.dispersy.authentication import DoubleMemberAuthentication, MemberAuthentication
from Tribler.dispersy.resolution import PublicResolution
from Tribler.dispersy.distribution import DirectDistribution
from Tribler.dispersy.destination import CandidateDestination
from Tribler.dispersy.community import Community
from Tribler.dispersy.message import Message
from Tribler.dispersy.crypto import ECCrypto
from Tribler.dispersy.conversion import DefaultConversion

from Tribler.community.multichain.payload import SignaturePayload, BlockRequestPayload, BlockResponsePayload
from Tribler.community.multichain.database import MultiChainDB, DatabaseBlock
from Tribler.community.multichain.conversion import MultiChainConversion, split_function

SIGNATURE = u"signature"
BLOCK_REQUEST = u"block_request"
BLOCK_RESPONSE = u"block_response"

""" ID of the first block of the chain. """
GENESIS_ID = '0'*20


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
        """
        Lock for operations on the chain. Only one operation can be pending on the chain at any time.
        Without locking the chain will be corrupted and branches will be created.
        This lock ensures that only one operation is pending.
        """
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
        # a81fdcb2db302ac15905d6e75f96b39ccdaf068bdbbda81a6356f53f7ce4e
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
                    self.received_signature_response),
            Message(self, BLOCK_REQUEST,
                    MemberAuthentication(),
                    PublicResolution(),
                    DirectDistribution(),
                    CandidateDestination(),
                    BlockRequestPayload(),
                    self._generic_timeline_check,
                    self.received_request_block),
            Message(self, BLOCK_RESPONSE,
                    MemberAuthentication(),
                    PublicResolution(),
                    DirectDistribution(),
                    CandidateDestination(),
                    BlockResponsePayload(),
                    self._generic_timeline_check,
                    self.received_block_response), ]

    def initiate_conversions(self):
        return [DefaultConversion(self), MultiChainConversion(self)]

    def publish_signature_request_message(self, candidate):
        """
        Creates and sends out a signed signature_request message.
        """
        self._logger.info("Sending signature request.")
        """
        Acquire chain lock to perform operations on the chain.
        The chain_lock is lifted after the timeout or a valid signature response is received.
        """
        self._logger.debug("Get Lock: send signature request: %s" % self.chain_lock.locked())
        self.chain_lock.acquire()
        self._logger.debug("Acquired Lock: send signature request.")

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
        total_up_requester, total_down_requester = self._get_next_total(up, down)
        # Instantiate the personal information
        sequence_number_requester = self._get_next_sequence_number()
        previous_hash_requester = self._get_latest_hash()

        payload = (up, down, total_up_requester, total_down_requester,
                   sequence_number_requester, previous_hash_requester)
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
        self._logger.debug("Chain Lock: process request: %s" % self.chain_lock.locked())
        # Check if the lock can be acquired without blocking to perform operations on the chain.
        if self.chain_lock.acquire(False):
            self._logger.debug("Chain Lock: acquired to process request.")
            # TODO: This code always signs a request. Checks and rejects should be inserted here!
            payload = message.payload

            total_up_responder, total_down_responder = self._get_next_total(payload.up, payload.down)
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
            # Operation on chain done, release the chain_lock for other operations.
            self.chain_lock.release()
            self._logger.info("Sending signature response.")
            return message
        else:
            self._logger.debug("Chain Lock: not acquired. Dropping request.")
            return None

    def allow_signature_response(self, request, response, modified):
        """
        We've received a signature response message after sending a request, we must return either:
            a. True, if we accept this message
            b. False, if not (because of inconsistencies in the payload)
        """
        if not response:
            self._logger.info("Release lock: Timeout received")
            # Operation failed release lock.
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
        self._logger.info("Valid %s signature response(s) received." % len(messages))
        for message in messages:
            if self.request_timeout_lock.acquire(False):
                # TODO: Check expecting response
                self.persist_signature_response(message)
                # Release lock because the operation is done.
                self._logger.info("Release lock: received signature response.")
                self.chain_lock.release()
                self.request_timeout_lock.release()

    def persist_signature_response(self, message):
        """
        Persist the signature response message.
        A hash will be created from the message and this will be used as an unique identifier.
        :param message:
        """
        block = DatabaseBlock.from_signature_response_message(message)
        self._logger.info("Persisting sr: %s" % base64.encodestring(block.id))
        self.persistence.add_block(block)

    def publish_request_block_message(self, candidate, sequence_number=-1):
        """
        Request a specific block from a chain of another candidate.
        :param candidate: The candidate that the block is requested from
        :param sequence_number: The requested sequence_number or default the latest sequence number
        """
        self._logger.info("Crawler: Requesting Block:%s" % sequence_number)
        meta = self.get_meta_message(BLOCK_REQUEST)

        message = meta.impl(authentication=(self.my_member,),
                            distribution=(self.claim_global_time(),),
                            destination=(candidate,),
                            payload=(sequence_number,))
        self.dispersy.store_update_forward([message], False, False, True)

    def received_request_block(self, messages):
        for message in messages:
            requested_sequence_number = message.payload.requested_sequence_number
            self._logger.info("Crawler: Received request for block: %s" % requested_sequence_number)
            self.publish_block(message.candidate, requested_sequence_number)

    def publish_block(self, candidate, sequence_number):
        requested_block = self.persistence.get_by_sequence_number_public_key(sequence_number, self._public_key)
        if requested_block:
            self._logger.info("Crawler: Sending block: %s" % sequence_number)
            meta = self.get_meta_message(BLOCK_RESPONSE)

            message = meta.impl(authentication=(self.my_member,),
                                distribution=(self.claim_global_time(),),
                                destination=(candidate,),
                                payload=requested_block.to_payload())

            self.dispersy.store_update_forward([message], False, False, True)
        else:
            self._logger.info("Crawler: Received invalid request for block: %s" % sequence_number)

    def received_block_response(self, messages):
        """
        We've received a valid block response and must process this message.
        """
        self._logger.info("Crawler: Valid %s block response(s) received." % len(messages))
        for message in messages:
            block = DatabaseBlock.from_block_response_message(message)
            # Create the hash of the message
            if not self.persistence.contains(block.id):
                self._logger.info("Crawler: Persisting sr: %s" % base64.encodestring(block.id))
                try:
                    self.persistence.add_block(block)
                except IntegrityError:
                    # A race condition can occur between here and
                    # the if statement checking if the DB already contains the block.
                    self._logger.error("Crawler: tried to save already known block.")
                # Crawl further down the chain.
                self.crawl_down(block.previous_hash_requester, block.sequence_number_requester-1,
                                block.public_key_requester)
                self.crawl_down(block.previous_hash_responder, block.sequence_number_responder-1,
                                block.public_key_responder)
            else:
                self._logger.info("Crawler: Received already known block")

    def crawl_down(self, next_hash, sequence_number, public_key):
        # Check if it is not the genesis block.
        if sequence_number > 0:
            # Check if the block is not already known.
            if not self.persistence.contains(next_hash):
                member = self.dispersy.get_member(public_key=public_key)
                candidate = self.get_candidate_mid(member.mid) if member else None
                # Check if the candidate is known.
                if candidate:
                    self._logger.info("Crawler: down: crawling down.")
                    self.publish_request_block_message(candidate, sequence_number)
                else:
                    self._logger.info("Crawler: down: candidate unknown.")
            else:
                self._logger.info("Crawler: down: reached known block.")
        else:
            self._logger.info("Crawler: down: reached genesis block.")

    def get_key(self):
        return self._ec

    def _get_next_total(self, up, down):
        """
        Returns the next total numbers of up and down incremented with the current interaction up and down metric.
        :param up: Up metric for the interaction.
        :param down: Down metric for the interaction.
        :return: (total_up (int), total_down (int)
        """
        total_up, total_down = self.persistence.get_total(self._public_key)
        if total_up == total_down == -1:
            return up, down
        else:
            return total_up + up, total_down + down

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