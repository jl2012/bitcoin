#!/usr/bin/env python3
# Copyright (c) 2014-2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from test_framework.mininode import *
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
from test_framework.blocktools import create_block, create_coinbase

'''
SendHeadersTest -- test behavior of headers messages to announce blocks.

Setup: 

- Two nodes, two p2p connections to node0. One p2p connection should only ever
  receive inv's (omitted from testing description below, this is our control).
  Second node is used for creating reorgs.

Part 1: No headers announcements before "sendheaders"
a. node mines a block [expect: inv]
   send getdata for the block [expect: block]
b. node mines another block [expect: inv]
   send getheaders and getdata [expect: headers, then block]
c. node mines another block [expect: inv]
   peer mines a block, announces with header [expect: getdata]
d. node mines another block [expect: inv]

Part 2: After "sendheaders", headers announcements should generally work.
a. peer sends sendheaders [expect: no response]
   peer sends getheaders with current tip [expect: no response]
b. node mines a block [expect: tip header]
c. for N in 1, ..., 10:
   * for announce-type in {inv, header}
     - peer mines N blocks, announces with announce-type
       [ expect: getheaders/getdata or getdata, deliver block(s) ]
     - node mines a block [ expect: 1 header ]

Part 3: Headers announcements stop after large reorg and resume after getheaders or inv from peer.
- For response-type in {inv, getheaders}
  * node mines a 7 block reorg [ expect: headers announcement of 8 blocks ]
  * node mines an 8-block reorg [ expect: inv at tip ]
  * peer responds with getblocks/getdata [expect: inv, blocks ]
  * node mines another block [ expect: inv at tip, peer sends getdata, expect: block ]
  * node mines another block at tip [ expect: inv ]
  * peer responds with getheaders with an old hashstop more than 8 blocks back [expect: headers]
  * peer requests block [ expect: block ]
  * node mines another block at tip [ expect: inv, peer sends getdata, expect: block ]
  * peer sends response-type [expect headers if getheaders, getheaders/getdata if mining new block]
  * node mines 1 block [expect: 1 header, peer responds with getdata]

Part 4: Test direct fetch behavior
a. Announce 2 old block headers.
   Expect: no getdata requests.
b. Announce 3 new blocks via 1 headers message.
   Expect: one getdata request for all 3 blocks.
   (Send blocks.)
c. Announce 1 header that forks off the last two blocks.
   Expect: no response.
d. Announce 1 more header that builds on that fork.
   Expect: one getdata request for two blocks.
e. Announce 16 more headers that build on that fork.
   Expect: getdata request for 14 more blocks.
f. Announce 1 more header that builds on that fork.
   Expect: no response.

Part 5: Test handling of headers that don't connect.
a. Repeat 10 times:
   1. Announce a header that doesn't connect.
      Expect: getheaders message
   2. Send headers chain.
      Expect: getdata for the missing blocks, tip update.
b. Then send 9 more headers that don't connect.
   Expect: getheaders message each time.
c. Announce a header that does connect.
   Expect: no response.
d. Announce 49 headers that don't connect.
   Expect: getheaders message each time.
e. Announce one more that doesn't connect.
   Expect: disconnect.
'''

direct_fetch_response_time = 0.05

class BaseNode(SingleNodeConnCB):
    def __init__(self):
        SingleNodeConnCB.__init__(self)
        self.last_inv = None
        self.last_headers = None
        self.last_block = None
        self.last_getdata = None
        self.block_announced = False
        self.last_getheaders = None
        self.disconnected = False
        self.last_blockhash_announced = None

    def clear_last_announcement(self):
        with mininode_lock:
            self.block_announced = False
            self.last_inv = None
            self.last_headers = None

    # Request data for a list of block hashes
    def get_data(self, block_hashes):
        msg = msg_getdata()
        for x in block_hashes:
            msg.inv.append(CInv(2, x))
        self.connection.send_message(msg)

    def get_headers(self, locator, hashstop):
        msg = msg_getheaders()
        msg.locator.vHave = locator
        msg.hashstop = hashstop
        self.connection.send_message(msg)

    def send_block_inv(self, blockhash):
        msg = msg_inv()
        msg.inv = [CInv(2, blockhash)]
        self.connection.send_message(msg)

    def on_inv(self, conn, message):
        self.last_inv = message
        self.block_announced = True
        self.last_blockhash_announced = message.inv[-1].hash

    def on_headers(self, conn, message):
        self.last_headers = message
        if len(message.headers):
            self.block_announced = True
            message.headers[-1].calc_sha256()
            self.last_blockhash_announced = message.headers[-1].sha256

    def on_block(self, conn, message):
        self.last_block = message.block
        self.last_block.calc_sha256()

    def on_getdata(self, conn, message):
        self.last_getdata = message

    def on_getheaders(self, conn, message):
        self.last_getheaders = message

    def on_close(self, conn):
        self.disconnected = True

    # Test whether the last announcement we received had the
    # right header or the right inv
    # inv and headers should be lists of block hashes
    def check_last_announcement(self, headers=None, inv=None):
        expect_headers = headers if headers != None else []
        expect_inv = inv if inv != None else []
        test_function = lambda: self.block_announced
        assert(wait_until(test_function, timeout=60))
        with mininode_lock:
            self.block_announced = False

            success = True
            compare_inv = []
            if self.last_inv != None:
                compare_inv = [x.hash for x in self.last_inv.inv]
            if compare_inv != expect_inv:
                success = False

            hash_headers = []
            if self.last_headers != None:
                # treat headers as a list of block hashes
                hash_headers = [ x.sha256 for x in self.last_headers.headers ]
            if hash_headers != expect_headers:
                success = False

            self.last_inv = None
            self.last_headers = None
        return success

    # Syncing helpers
    def wait_for_block(self, blockhash, timeout=60):
        test_function = lambda: self.last_block != None and self.last_block.sha256 == blockhash
        assert(wait_until(test_function, timeout=timeout))
        return

    def wait_for_getheaders(self, timeout=60):
        test_function = lambda: self.last_getheaders != None
        assert(wait_until(test_function, timeout=timeout))
        return

    def wait_for_getdata(self, hash_list, timeout=60):
        if hash_list == []:
            return

        test_function = lambda: self.last_getdata != None and [x.hash for x in self.last_getdata.inv] == hash_list
        assert(wait_until(test_function, timeout=timeout))
        return

    def wait_for_disconnect(self, timeout=60):
        test_function = lambda: self.disconnected
        assert(wait_until(test_function, timeout=timeout))
        return

    def wait_for_block_announcement(self, block_hash, timeout=60):
        test_function = lambda: self.last_blockhash_announced == block_hash
        assert(wait_until(test_function, timeout=timeout))
        return

    def send_header_for_blocks(self, new_blocks):
        headers_message = msg_headers()
        headers_message.headers = [ CBlockHeader(b) for b in new_blocks ]
        self.send_message(headers_message)

    def send_getblocks(self, locator):
        getblocks_message = msg_getblocks()
        getblocks_message.locator.vHave = locator
        self.send_message(getblocks_message)

# InvNode: This peer should only ever receive inv's, because it doesn't ever send a
# "sendheaders" message.
class InvNode(BaseNode):
    def __init__(self):
        BaseNode.__init__(self)

# TestNode: This peer is the one we use for most of the testing.
class TestNode(BaseNode):
    def __init__(self):
        BaseNode.__init__(self)

class SendHeadersTest(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.setup_clean_chain = True
        self.num_nodes = 2

    def setup_network(self):
        self.nodes = []
        self.nodes = start_nodes(self.num_nodes, self.options.tmpdir, [["-debug", "-logtimemicros=1"]]*2)
        # connect_nodes(self.nodes[0], 1)

    # mine count blocks and return the new tip
    def mine_blocks(self, count, node = 0):
        # Clear out last block announcement from each p2p listener
        [ x.clear_last_announcement() for x in self.p2p_connections ]
        self.nodes[node].generate(count)
        return int(self.nodes[node].getbestblockhash(), 16)

    # mine a reorg that invalidates length blocks (replacing them with
    # length+1 blocks).
    # Note: we clear the state of our p2p connections after the
    # to-be-reorged-out blocks are mined, so that we don't break later tests.
    # return the list of block hashes newly mined
    def mine_reorg(self, length):
        self.nodes[0].generate(length) # make sure all invalidated blocks are node0's
        sync_blocks(self.nodes, wait=0.1)
        for x in self.p2p_connections:
            x.wait_for_block_announcement(int(self.nodes[0].getbestblockhash(), 16))
            x.clear_last_announcement()

        tip_height = self.nodes[1].getblockcount()
        hash_to_invalidate = self.nodes[1].getblockhash(tip_height-(length-1))
        self.nodes[1].invalidateblock(hash_to_invalidate)
        all_hashes = self.nodes[1].generate(length+1) # Must be longer than the orig chain
        sync_blocks(self.nodes, wait=0.1)
        return [int(x, 16) for x in all_hashes]

    def run_test(self):
        # Setup the p2p connections and start up the network thread.
        inv_node = InvNode()
        test_node = TestNode()

        self.p2p_connections = [inv_node, test_node]

        connections = []
        connections.append(NodeConn('127.0.0.1', p2p_port(0), self.nodes[0], inv_node))
        # Set nServices to 0 for test_node, so no block download will occur outside of
        # direct fetching
        connections.append(NodeConn('127.0.0.1', p2p_port(0), self.nodes[0], test_node, services=0))
        inv_node.add_connection(connections[0])
        test_node.add_connection(connections[1])

        NetworkThread().start() # Start up network handling in another thread

        # Test logic begins here
        inv_node.wait_for_verack()
        test_node.wait_for_verack()

        tip = int(self.nodes[0].getbestblockhash(), 16)

        # PART 1
        # 1. Mine a block; expect inv announcements each time
        print("Part 1: headers don't start before sendheaders message...")
        for i in range(1):
            old_tip = tip
            tip = self.mine_blocks(1)
            # assert_equal(inv_node.check_last_announcement(inv=[tip]), True)
            # assert_equal(test_node.check_last_announcement(inv=[tip]), True)
            # this time announce own block via headers
            height = self.nodes[0].getblockcount()
            last_time = self.nodes[0].getblock(self.nodes[0].getbestblockhash())['time']
            block_time = last_time + 1

            block_time += 1
            height += 1
            new_block = create_block(tip, create_coinbase(height), block_time)
            new_block.nVersion = -1
            new_block.vtx[0].nLockTime = 10
            new_block.vtx[0].vin[0].nSequence = 0
            new_block.vtx[0].rehash()
            new_block.hashMerkleRoot = new_block.calc_merkle_root()
            new_block.rehash()
            new_block.solve()
            test_node.send_header_for_blocks([new_block])
            tip = new_block.sha256
            print (bytes_to_hex_str(new_block.serialize()))
            print (self.nodes[0].submitblock(bytes_to_hex_str(new_block.serialize())))
            print (new_block.hash)


            for j in range(10):
                block_time += 1
                height += 1
                new_block = create_block(tip, create_coinbase(height), block_time)
                new_block.nVersion = 1
                new_block.solve()
                test_node.send_header_for_blocks([new_block])
                tip = new_block.sha256
                print (bytes_to_hex_str(new_block.serialize()))
                print (self.nodes[0].submitblock(bytes_to_hex_str(new_block.serialize())))
                print (new_block.hash)

            print (self.nodes[0].getinfo())
            self.nodes[0].generate(1)
            print (self.nodes[0].getinfo())

        print("Part 1: success!")
        assert(False)

if __name__ == '__main__':
    SendHeadersTest().main()
