"""
This file contains the tests for the community.py for MultiChain community.
"""
import uuid
import logging

from Tribler.Test.test_as_server import BaseTestCase

from Tribler.community.multichain.community import MultiChainScheduler


class TestMultiChainScheduler(BaseTestCase):
    """
    Class that tests the MultiChainScheduler
    """

    data_threshold = MultiChainScheduler.threshold
    peer1 = ("127.0.0.1", 80)

    def __init__(self, *args, **kwargs):
        super(TestMultiChainScheduler, self).__init__(*args, **kwargs)

    class TestCandidate:
        """
        A mock candidate to test the MultiChainScheduler.
        """

        class TestMember:
            def __init__(self):
                self.mid = self.mid = uuid.uuid4()

        def __init__(self):
            self.member = self.TestMember()

        def get_member(self):
            return self.member

    class TestSchedulerCommunity:
        """
        A mock community to test the MultiChainScheduler.
        """

        def __init__(self, candidate):
            self.logger = logging.getLogger(self.__class__.__name__)
            self.signature_requested_tried = False
            self.signature_requested = False
            self.candidate = candidate
            self.publish_success = True
            return

        def get_candidate(self, peer):
            return self.candidate

        def try_to_publish_signature_request_message(self, candidate, up, down):
            self.signature_requested_tried = True
            if self.publish_success:
                self.publish_signature_request_message(candidate, up, down)
                return True
            else:
                return False

        def publish_signature_request_message(self, candidate, up, down):
            self.signature_requested = True

    def setUp(self, annotate=True):
        super(TestMultiChainScheduler, self).setUp()
        self.candidate = self.TestCandidate()
        self.community = self.TestSchedulerCommunity(self.candidate)
        self.scheduler = MultiChainScheduler(self.community)

    def tearDown(self, annotate=True):
        super(TestMultiChainScheduler, self).tearDown()
        self.candidate = None
        self.community = None
        self.scheduler = None

    def test_update_amount_send_empty(self):
        """
        The scheduler can track the amount for a new candidate.
        """
        # Arrange
        amount = self.data_threshold / 2
        # Act
        self.scheduler.update_amount_send(self.peer1, amount)
        # Assert
        self.assertEqual(amount, self.scheduler._outstanding_amount_send[self.peer1])

    def test_update_amount_send_add(self):
        """
        The scheduler can track the amount when adding to a previous amount.
        """
        # Arrange
        first_amount = (self.data_threshold - 10) / 2
        second_amount = (self.data_threshold - 10) / 2
        self.scheduler.update_amount_send(self.peer1, first_amount)
        # Act
        self.scheduler.update_amount_send(self.peer1, second_amount)
        # Assert
        self.assertEqual(first_amount + second_amount,
                         self.scheduler._outstanding_amount_send[self.peer1])
        self.assertFalse(self.community.signature_requested_tried)

    def test_update_amount_send_above_threshold(self):
        """
        The scheduler schedules a signature request if the amount is above the threshold.
        """
        # Arrange
        amount = self.data_threshold + 10
        # Act
        self.scheduler.update_amount_send(self.peer1, amount)
        # Assert
        """ The dictionary should be rid of the entry for the mid."""
        self.assertFalse(self.peer1 in self.scheduler._outstanding_amount_send.keys())
        self.assertTrue(self.community.signature_requested_tried)

    def test_update_amount_send_no_candidate(self):
        """
        The scheduler does not schedule a signature request, because candidate is not available.
        """
        amount = self.data_threshold + 10
        self.community.candidate = None
        # Act
        self.scheduler.update_amount_send(self.peer1, amount)
        # Assert
        """ A amount should be left open """
        self.assertEqual(amount, self.scheduler._outstanding_amount_send[self.peer1])
        self.assertFalse(self.community.signature_requested_tried)

    def test_update_amount_send_failed(self):
        """
        The scheduler schedules a signature request but fails and should remember the amount.
        """
        # Arrange
        amount = self.data_threshold + 10
        self.community.publish_success = False
        # Act
        self.scheduler.update_amount_send(self.peer1, amount)
        # Assert
        """ The whole amount should be left open."""
        self.assertEqual(amount, self.scheduler._outstanding_amount_send[self.peer1])
        self.assertTrue(self.community.signature_requested_tried)

    def test_update_amount_received_empty(self):
        """
        The scheduler can track the amount for a new candidate.
        """
        # Arrange
        amount = self.data_threshold / 2
        # Act
        self.scheduler.update_amount_received(self.peer1, amount)
        # Assert
        self.assertEqual(amount, self.scheduler._outstanding_amount_received[self.peer1])
        self.assertFalse(self.community.signature_requested_tried)

    def test_update_amount_received_add(self):
        """
        The scheduler can track the amount when adding to a previous amount.
        """
        # Arrange
        first_amount = (self.data_threshold - 10) / 2
        second_amount = (self.data_threshold - 10) / 2
        self.scheduler.update_amount_received(self.peer1, first_amount)
        # Act
        self.scheduler.update_amount_received(self.peer1, second_amount)
        # Assert
        self.assertEqual(first_amount + second_amount,
                         self.scheduler._outstanding_amount_received[self.peer1])
        self.assertFalse(self.community.signature_requested_tried)

    def test_update_amount_received_above_threshold(self):
        """
        The scheduler does not schedule a signature request if the amount is above the threshold,
        but the chain is not available.
        """
        amount = self.data_threshold + 10
        # Act
        self.scheduler.update_amount_received(self.peer1, amount)
        # Assert
        """ A amount should be left open """
        self.assertEqual(amount, self.scheduler._outstanding_amount_received[self.peer1])
        self.assertFalse(self.community.signature_requested_tried)

    def test_schedule_additional_signature_request_1_above_threshold(self):
        """
        The scheduler schedules an additional signature request, because a peer is above the threshold.
        """
        # Arrange
        amount = self.data_threshold + 10
        self.scheduler._outstanding_amount_send[self.peer1] = amount
        # Act
        result = self.scheduler.notify_done()
        # Assert
        self.assertTrue(result)
        self.assertTrue(self.community.signature_requested)

    def test_schedule_additional_signature_request_0_above_threshold(self):
        """
        The scheduler schedules no additional signature request,
        because no peer is above the threshold.
        """
        # Arrange
        amount = self.data_threshold / 2
        self.scheduler._outstanding_amount_send[self.peer1] = amount
        # Act
        result = self.scheduler.notify_done()
        # Assert
        self.assertFalse(result)
        self.assertFalse(self.community.signature_requested)
        self.assertEqual(amount, self.scheduler._outstanding_amount_send[self.peer1])

    def test_schedule_additional_signature_request_no_candidate(self):
        """
        The scheduler schedules no additional signature request,
        because no candidate is found.
        """
        # Arrange
        amount = self.data_threshold + 10
        self.scheduler._outstanding_amount_send[self.peer1] = amount
        self.community.candidate = None
        # Act
        result = self.scheduler.notify_done()
        # Assert
        self.assertFalse(result)
        self.assertFalse(self.community.signature_requested)
        self.assertEqual(amount, self.scheduler._outstanding_amount_send[self.peer1])