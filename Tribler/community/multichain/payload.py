from Tribler.dispersy.payload import Payload
from hashlib import sha1

EMPTY_HASH = sha1('').digest()


class SignaturePayload(Payload):
    """
    Payload for message that will respond to a Signature Request containing
    the Signature of {timestamp,signature_requester}.
    """

    class Implementation(Payload.Implementation):
        def __init__(self, meta, up, down, total_up_requester, total_down_requester,
                     sequence_number_requester, previous_hash_requester,
                     total_up_responder=-1, total_down_responder=-1,
                     sequence_number_responder=-1, previous_hash_responder=''):
            super(SignaturePayload.Implementation, self).__init__(meta)
            """ Set the interaction part of the message """
            self._up = up
            self._down = down
            """ Set the requester part of the message """
            self._total_up_requester = total_up_requester
            self._total_down_requester = total_down_requester
            self._sequence_number_requester = sequence_number_requester
            self._previous_hash_requester = previous_hash_requester
            """ Set the responder part of the message. """
            self._total_up_responder = total_up_responder
            self._total_down_responder = total_down_responder
            self._sequence_number_responder = sequence_number_responder
            self._previous_hash_responder = previous_hash_responder if previous_hash_responder \
                else EMPTY_HASH

        @property
        def up(self):
            return self._up

        @property
        def down(self):
            return self._down

        @property
        def total_up_requester(self):
            return self._total_up_requester

        @property
        def total_down_requester(self):
            return self._total_down_requester

        @property
        def sequence_number_requester(self):
            return self._sequence_number_requester

        @property
        def previous_hash_requester(self):
            return self._previous_hash_requester

        @property
        def total_up_responder(self):
            return self._total_up_responder

        @property
        def total_down_responder(self):
            return self._total_down_responder

        @property
        def sequence_number_responder(self):
            return self._sequence_number_responder

        @property
        def previous_hash_responder(self):
            return self._previous_hash_responder