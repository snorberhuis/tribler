""" This file contains everything related to persistence for MultiChain.
"""
from os import path

from Tribler.dispersy.database import Database

DATABASE_DIRECTORY = path.join(u"sqlite")
""" Path to the database location + dispersy._workingdirectory"""
DATABASE_PATH = path.join(DATABASE_DIRECTORY, u"multichain.db")
""" Version to keep track if the db schema needs to be updated."""
LATEST_DB_VERSION = 1
""" Schema for the MultiChain DB."""
schema = u"""
CREATE TABLE IF NOT EXISTS multi_chain(
 block_hash			        text PRIMARY KEY,
 previous_hash_requester	text NOT NULL,
 public_key_requester		text NOT NULL,
 signature_requester		text NOT NULL,
 previous_hash_responder	text NOT NULL,
 public_key_responder		text NOT NULL,
 signature_responder		text NOT NULL,
 sequence_number_requester  integer NOT NULL,
 sequence_number_responder  integer NOT NULL,
 up                         integer NOT NULL,
 down                       integer NOT NULL,
 total_up                   integer NOT NULL,
 total_down                 integer NOT NULL
);

CREATE TABLE option(key TEXT PRIMARY KEY, value BLOB);
INSERT INTO option(key, value) VALUES('database_version', '""" + str(LATEST_DB_VERSION) + u"""');
"""


class MultiChainDB(Database):
    """
    Persistence layer for the MultiChain Community.
    Connection layer to SQLiteDB.
    Ensures a proper DB schema on startup.
    """
    def __init__(self, working_directory):
        """
        Sets up the persistence layer ready for use.
        :param working_directory: Path to the working directory
        that will contain the the db at workingdirectory/DATABASE_PATH
        :return:
        """
        super(MultiChainDB, self).__init__(path.join(working_directory, DATABASE_PATH))

        self.open()

    def add_block(self, block_id, block):
        """
        Persist a block under a block_id
        :param block_id: The ID the block is saved under. This is the hash of the block.
        :param block: The data that will be saved.
        """
        data = (buffer(block_id), buffer(block.previous_hash_requester), buffer(block.public_key_requester),
                buffer(block.signature_requester), buffer(block.previous_hash_responder),
                buffer(block.public_key_responder), buffer(block.signature_responder),
                block.sequence_number_requester, block.sequence_number_responder, block.up, block.down, block.total_up,
                block.total_down)

        self.execute(
            u"INSERT INTO multi_chain (block_hash, previous_hash_requester, public_key_requester, "
            u"signature_requester, previous_hash_responder, public_key_responder, signature_responder,"
            u" sequence_number_requester, sequence_number_responder, up, down, total_up, total_down) "
            u"values(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            data)

    def get_previous_id(self, public_key):
        """
        Get the id of the latest block in the chain for a specific public key.
        :param public_key: The PK for which the latest hash has to be found.
        :return: block_id
        """
        public_key = buffer(public_key)
        db_query = u"SELECT block_hash, MAX(sequence_number) FROM " \
                   u"(SELECT block_hash, sequence_number_requester as sequence_number FROM multi_chain " \
                   u"WHERE public_key_requester == ? UNION SELECT block_hash, sequence_number_responder " \
                   u"FROM multi_chain WHERE public_key_responder = ?)"

        db_result = self.execute(db_query, (public_key, public_key)).fetchone()[0]

        return str(db_result) if db_result else None

    def get(self, block_id):
        """
        Returns a block saved in the persistence
        :param block_id: The id of the block that needs to be retrieved.
        """
        db_query = u"SELECT previous_hash_requester, public_key_requester, signature_requester," \
                   u" previous_hash_responder, public_key_responder, signature_responder, sequence_number_requester," \
                   u" sequence_number_responder, up, down, total_up, total_down " \
                   u"FROM `multi_chain` WHERE block_hash = ? LIMIT 1"
        db_result = self.execute(db_query, (buffer(block_id),)).fetchone()
        # Decode the DB format and create a DB block
        return DatabaseBlock(db_result) if db_result else None

    def get_ids(self):
        """
        Get all the IDs saved in the persistence layer.
        :return: list of ids.
        """
        db_result = self.execute(u"SELECT block_hash from multi_chain").fetchall()
        # Unpack the db_result tuples and decode the results.
        return [str(x[0]) for x in db_result]

    def contains(self, block_id):
        """
        Check if a block is existent in the persistence layer.
        :param block_id: The id t hat needs to be checked.
        :return: True if the block exists, else false.
        """
        db_query = u"SELECT block_hash from multi_chain where block_hash == ? LIMIT 1"
        db_result = self.execute(db_query, (buffer(block_id),)).fetchone()
        return db_result is not None

    def contains_signature(self, signature_requester, public_key_requester):
        """
        Check if a block is existent in the persistence layer based on a signature and public key pair.
        :param signature_requester: The id t hat needs to be checked.
        :return: True if the block exists, else false.
        :rtype : bool
        """
        db_query = u"SELECT block_hash from multi_chain " \
                   u"WHERE public_key_requester == ? and signature_requester == ? LIMIT 1"
        db_result = self.execute(db_query, (buffer(public_key_requester), buffer(signature_requester))).fetchone()
        return db_result is not None

    def get_latest_sequence_number(self, public_key):
        """
        Return the latest sequence number known in this node.
        If no block for the pk is know returns -1.
        :param public_key: Corresponding public key
        :return: sequence number (integer) or -1 if no block is known
        """
        public_key = buffer(public_key)
        db_query = u"SELECT MAX(sequence_number) FROM (SELECT sequence_number_requester as sequence_number " \
                   u"FROM multi_chain WHERE public_key_requester == ? UNION " \
                   u"SELECT sequence_number_responder from multi_chain WHERE public_key_responder = ? )"
        db_result = self.execute(db_query, (public_key, public_key)).fetchone()[0]
        return db_result if db_result else -1

    def open(self, initial_statements=True, prepare_visioning=True):
        return super(MultiChainDB, self).open(initial_statements, prepare_visioning)

    def close(self, commit=True):
        return super(MultiChainDB, self).close(commit)

    def cleanup(self):
        self.executescript(cleanup)

    def check_database(self, database_version):
        """
        Ensure the proper schema is used by the database.
        :param database_version: Current version of the database.
        :return:
        """
        assert isinstance(database_version, unicode)
        assert database_version.isdigit()
        assert int(database_version) >= 0
        database_version = int(database_version)

        if database_version < 1:
            self.executescript(schema)
            self.commit()

        return LATEST_DB_VERSION

    @staticmethod
    def _convert_to_database_block(db_result):
        data = ()
        for x in range(0, len(db_result)):
            if x <= 6:
                data += (str(db_result[x]),)
            else:
                data += (db_result[x],)
        return DatabaseBlock(data)


class DatabaseBlock:
    """ DataClass for a block that comes out of the DB.
    """

    def __init__(self, data):
        """ Set the partial signature of the requester of the block."""
        self.previous_hash_requester = str(data[0])
        self.public_key_requester = str(data[1])
        self.signature_requester = str(data[2])
        """ Set the partial signature of the responder of the block."""
        self.previous_hash_responder = str(data[3])
        self.public_key_responder = str(data[4])
        self.signature_responder = str(data[5])
        """ Set the payload of the block """
        self.sequence_number_requester = data[6]
        self.sequence_number_responder = data[7]
        self.up = data[8]
        self.down = data[9]
        self.total_up = data[10]
        self.total_down = data[11]