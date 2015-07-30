from Tribler.dispersy.payload import Payload
from hashlib import sha1


class SignaturePayload(Payload):
    """
    Payload for message that will respond to a Signature Request containing
    the Signature of {timestamp,signature_requester}.
    """

    class Implementation(Payload.Implementation):

        def __init__(self, meta, up, down, total_up, total_down,
                     sequence_number_requester, previous_hash_requester,
                     sequence_number_responder=-1, previous_hash_responder=''):
            super(SignaturePayload.Implementation, self).__init__(meta)
            self._up = up
            self._down = down
            self._total_up = total_up
            self._total_down = total_down
            """ Set the partial signature of the requester in the payload of the message."""
            self._sequence_number_requester = sequence_number_requester
            self._previous_hash_requester = previous_hash_requester
            """ Set the partial signature of the responder in the payload of the message."""
            self._sequence_number_responder = sequence_number_responder
            self._previous_hash_responder = previous_hash_responder if previous_hash_responder \
                else sha1(previous_hash_responder).digest()

        @property
        def up(self):
            return self._up

        @property
        def down(self):
            return self._down

        @property
        def total_up(self):
            return self._total_up

        @property
        def total_down(self):
            return self._total_down

        @property
        def sequence_number_requester(self):
            return self._sequence_number_requester

        @property
        def previous_hash_requester(self):
            return self._previous_hash_requester

        @property
        def sequence_number_responder(self):
            return self._sequence_number_responder

        @property
        def previous_hash_responder(self):
            return self._previous_hash_responder