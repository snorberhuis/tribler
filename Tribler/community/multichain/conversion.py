"""
File contains all conversions for the MultiChain Community.
"""
from struct import pack, unpack_from, calcsize

from Tribler.dispersy.conversion import BinaryConversion
from Tribler.dispersy.message import DropPacket

"""
Hash length used in the MultiChain Community
"""
# Calculated with sha1("").digest_size
HASH_LENGTH = 20
"""
Formatting of the signature packet
"""
# Sequence_number, previous_hash
append_format = 'i ' + str(HASH_LENGTH) + 's'
# Up, Down, TotalUp, TotalDown, sequence_number_requester, previous_hash_requester,
#   sequence_number_responder, previous_hash_responder]
signature_format = ' '.join(['!I I I I', append_format, append_format])
signature_size = calcsize(signature_format)
append_size = calcsize(append_format)


class MultiChainConversion(BinaryConversion):
    """
    Class that handles all encoding and decoding of MultiChain messages.
    """

    def __init__(self, community):
        super(MultiChainConversion, self).__init__(community, "\x01")
        from Tribler.community.multichain.community import SIGNATURE

        # Define Request Signature.
        self.define_meta_message(chr(1), community.get_meta_message(SIGNATURE),
                                 self._encode_signature, self._decode_signature)

    def _encode_signature(self, message):
        """
        Encode the signature message
        :param message: Message.impl of SIGNATURE
        :return: encoding ready to be sent of the network.
        """
        payload = message.payload
        return pack(signature_format, *(payload.up, payload.down, payload.total_up, payload.total_down,
                                        payload.sequence_number_requester, payload.previous_hash_requester,
                                        payload.sequence_number_responder, payload.previous_hash_responder)),

    def _decode_signature(self, placeholder, offset, data):
        """
        Decode an incoming signature message
        :param placeholder:
        :param offset: Start of the SIGNATURE message in the data.
        :param data: ByteStream containing the message.
        :return: (offset, SIGNATURE.impl)
        """
        if len(data) < offset + signature_size:
            raise DropPacket("Unable to decode the payload")

        values = unpack_from(signature_format, data, offset)
        offset += signature_size

        if len(values) != 8:
            raise DropPacket("Unable to decode the signature")

        return \
            offset, placeholder.meta.payload.implement(*values)


def split_function(payload):
    """
    This function splits the SIGNATURE MESSAGE in parts.
    The first to be signed by the requester, and the second the whole message to be signed by the responder
    :param payload: Encoded message to be split
    :return: (first_part, whole)
    """
    return payload[:-append_size], payload