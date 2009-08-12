#!/usr/bin/python2.5
#
# Copyright 2009 Google Inc.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""A receiver-side implementation of the BGP Monitoring Protocol (BMP)."""

__author__ = "sstuart@google.com (Stephen Stuart)"

import array
import getopt
import socket
import struct
import sys
import time
import BGP
import BMP

# constants
#
HOST = ""
PORT = 0
INDENT_CHAR = " "
INDENT_COUNT = 2

# global variables
#
RECORD_SESSION = 0
DEBUG_FLAG = 0


# function to collect a BMP header
#
def CollectBmpHeader(s, verbose=0):
  """Collect a BMP header.

  Args:
    s: socket from which to read.
    verbose: be chatty, or not.

  Returns:
    an int indicating the type of message that follows the header.
  """

  print_msg = []

  # read the fixed-length header from the socket
  #
  header = CollectBytes(s, BMP.HEADER_LEN)

  # unpack and decide what to print
  #
  version, msg_type, peer_type, peer_flags = struct.unpack(">BBBB",
                                                           header[0:4])
  print_msg.append("BMP version " + str(version))
  print_msg.append(" msg_type " + BMP.MSG_TYPE_STR[msg_type])
  if verbose:
    print_msg.append(" peer_type " + BMP.PEER_TYPE_STR[peer_type])
    print_msg.append(" peer_flags 0x%x\n" % peer_flags)
  else:
    print_msg.append("\n")
  if (peer_flags & BMP.PEER_FLAG_IPV6) == BMP.PEER_FLAG_IPV6:
    peer_address = socket.inet_ntop(socket.AF_INET6, header[12:28])
  else:
    peer_address = socket.inet_ntop(socket.AF_INET, header[24:28])
  if verbose:
    print_msg.append("  peer_address " + peer_address)
    peer_as, time_sec = struct.unpack(">LxxxxL",
                                      header[28:40])
    print_msg.append(" as " + str(peer_as))
    print_msg.append(" router_id " + socket.inet_ntoa(header[32:36]) + "\n")
    print_msg.append("  time " + time.ctime(time_sec) + "\n")

  # print the message
  #
  print "".join(print_msg),

  # if we have a version mismatch, we're pretty much done here
  #
  assert (version == BMP.VERSION), "BMP version mismatch"

  # return the message type so the caller can decide what to do next
  #
  return msg_type


# function to collect a BMP peer down notification
#
def CollectBmpPeerDown(s, verbose=0):
  """Collect a BMP Peer Down message.

  Args:
    s: socket from which to read.
    verbose: be chatty, or not.

  Returns:
    nothing
  """

  indent = INDENT_CHAR * INDENT_COUNT

  reason_code = CollectBytes(s, 1)
  if reason_code[0] == 1:
    print indent + "Local system closed session, notification sent"
    CollectBgpNotification(s, verbose)
  elif reason_code[0] == 2:
    print indent + "Local system closed session, no notification"
  elif reason_code[0] == 3:
    print indent + "Remote system closed session, notification sent"
    CollectBgpNotification(s, verbose)
  elif reason_code[0] == 4:
    print indent + "Remote system closed session, no notification"
  else:
    assert False, "unknown Peer Down reason code"


# function to collect a BMP statistics report
#
def CollectBmpSrMsg(s, verbose=0):
  """Collect a BMP Statistics Report message.

  Args:
    s: socket from which to read.
    verbose: be chatty, or not.

  Returns:
    nothing
  """

  print_msg = []
  indent = INDENT_CHAR * INDENT_COUNT

  # find out many TLVs there are
  #
  stats_count_buf = CollectBytes(s, 4)
  stats_count = struct.unpack(">L", stats_count_buf)[0]
  print_msg.append(indent + str(stats_count) + " TLVs present\n")

  # read all the TLVs
  #
  while stats_count > 0:
    stat_type_len_buf = CollectBytes(s, 4)
    stat_type, stat_len = struct.unpack(">HH", stat_type_len_buf)
    stat_data_buf = CollectBytes(s, stat_len)
    if stat_type in BMP.SR_TYPE_STR:
      assert stat_len == 4
      stat_val = struct.unpack(">L", stat_data_buf)[0]
      if verbose:
        print_msg.append(indent + indent + str(stat_val) + " ")
        print_msg.append(BMP.SR_TYPE_STR[stat_type] + "\n")
    stats_count -= 1

  # print the message
  #
  print "".join(print_msg),


# function to collect the header of a BGP PDU
# RFC4271 section 4.1
#
def CollectBgpHeader(s, verbose=0):
  """Collect a BGP header.

  Args:
    s: socket from which to read.
    verbose: be chatty, or not.

  Returns:
    an int indicating the length of the rest of the BGP message.
  """

  global DEBUG_FLAG

  indent = INDENT_CHAR * INDENT_COUNT

  # get the header
  #
  header = CollectBytes(s, BGP.HEADER_LEN)

  try:

    # verify that the marker is correct
    #
    for x in range(0, 15):
      assert header[x] == 255

    # unpack the length and type
    #
    length, msg_type = struct.unpack(">HB", header[16:19])
    print indent + "BGP " + BGP.MSG_TYPE_STR[msg_type],
    if verbose:
      print "length %d" % (length - BGP.HEADER_LEN)
    else:
      print

    # return the length of the rest of the PDU, and its type
    #
    return length - BGP.HEADER_LEN, msg_type

  except Exception:
    hex_dump = []
    for x in range(BGP.HEADER_LEN):
      hex_dump.append("0x%x" % struct.unpack("B", header[x]))
    print " ".join(hex_dump)
    raise Exception("parse error")


# function to collect a BGP notification PDU
# RFC4271 section 4.5
#
def CollectBgpNotification(s, verbose=0):
  """Collect a BMP Notification message.

  Args:
    s: socket from which to read.
    verbose: be chatty, or not.

  Returns:
    nothing
  """

  print_msg = []
  indent = INDENT_CHAR * (INDENT_COUNT * 2)

  # get the header
  #
  length, msg_type = CollectBgpHeader(s)
  assert msg_type == BGP.NOTIFICATION

  # get the rest of the PDU
  #
  notification = CollectBytes(s, length)
  code, subcode = struct.unpack(">BB", notification[0:2])
  print_msg.append(indent + "NOTIFICATION code " + str(code) +
                   " subcode " + str(subcode) + "\n")

  # if there are data bytes, dump them in hex
  #
  if (length > 2) and verbose:
    print_msg.append(indent + "NOTIFICATION data ")
    for x in range(3, length - 1):
      print_msg.append(" 0x%x" % notification[x])
    print_msg.append("\n")

  # print the message
  #
  print "".join(print_msg),


# function to collect a BGP update PDU
# RFC1997
# RFC2858
# RFC4271 section 4.3
# RFC4893
#
def CollectBgpUpdate(s, rfc4893_updates=0, verbose=0):
  """Collect a BMP Update message.

  Args:
    s: socket from which to read.
    rfc4893_updates: true if update conforms to RFC4893
    verbose: be chatty, or not.

  Returns:
    nothing
  """

  print_msg = []
  indent = INDENT_CHAR * (INDENT_COUNT * 2)

  # get the header
  #
  length, msg_type = CollectBgpHeader(s, verbose)
  assert msg_type == BGP.UPDATE

  # get the rest of the PDU
  #
  update = CollectBytes(s, length)

  # start parsing at offset 0
  #
  offset = 0

  # next section is withdrawn routes
  #
  withdrawn_route_len = struct.unpack_from(">H", update[0:2], offset)[0]
  if verbose:
    print(indent + "withdrawn at " + str(offset) +
          " length " + str(withdrawn_route_len))
  offset += 2
  if withdrawn_route_len:
    withdrawn_text = ParseBgpNlri(update,
                                  offset,
                                  offset + withdrawn_route_len,
                                  BGP.AF_IP,
                                  verbose)
    if withdrawn_text:
      prepend_str = indent + "withdraw "
      sep = "\n" + prepend_str
      print_msg.append(prepend_str + sep.join(withdrawn_text) + "\n")

    offset += withdrawn_route_len

  # next section is path attributes
  #
  path_attr_len = struct.unpack_from(">H", update, offset)[0]
  if verbose:
    print(indent + "path attributes at " + str(offset) +
          " length " + str(path_attr_len))
  offset += 2
  path_attr_end = offset + path_attr_len
  while offset < path_attr_end:

    # get flags and type code
    #
    attr_flags, attr_type_code = struct.unpack_from(">BB", update, offset)
    if verbose:
      print_msg.append(indent +
                       "path attr " +
                       BGP.ATTR_TYPE_STR[attr_type_code] +
                       " at " +
                       str(offset))
      print_msg.append(" flags 0x%x (" % attr_flags)
      attr_list = []
      if (attr_flags & BGP.ATTR_FLAG_OPTIONAL) == BGP.ATTR_FLAG_OPTIONAL:
        attr_list.append("optional")
      if (attr_flags & BGP.ATTR_FLAG_TRANSITIVE) == BGP.ATTR_FLAG_TRANSITIVE:
        attr_list.append("transitive")
      if (attr_flags & BGP.ATTR_FLAG_PARTIAL) == BGP.ATTR_FLAG_PARTIAL:
        attr_list.append("partial")
      if (attr_flags & BGP.ATTR_FLAG_EXT_LEN) == BGP.ATTR_FLAG_EXT_LEN:
        attr_list.append("extended-length")
      print_msg.append(" ".join(attr_list))
    offset += 2

    # check for extended length
    #
    if (attr_flags & BGP.ATTR_FLAG_EXT_LEN) == BGP.ATTR_FLAG_EXT_LEN:
      attr_len = struct.unpack_from(">H", update, offset)[0]
      offset += 2
    else:
      attr_len = update[offset]
      offset += 1

    if verbose:
      print_msg.append(")\n")

    # origin
    #
    if attr_type_code == BGP.ATTR_TYPE_ORIGIN:
      assert attr_len == 1, "attr_len wrong"
      print_msg.append(indent + BGP.ATTR_TYPE_STR[attr_type_code] + " ")
      print_msg.append(BGP.ORIGIN_STR[update[offset]])
      print_msg.append("\n")

    # AS path
    #
    elif attr_type_code == BGP.ATTR_TYPE_AS_PATH:
      print_msg.append(indent + BGP.ATTR_TYPE_STR[attr_type_code] + " ")

      # make a local copy of offset
      #
      offset2 = offset

      # walk through the path segments; 
      #
      while offset2 < (offset + attr_len):
        path_seg_type = update[offset2]
        offset2 += 1
        path_seg_len = update[offset2]
        offset2 += 1
        path_seg_val = []
        for x in range(path_seg_len):

          # RFC4893-style updates have 4-octet ASNs, otherwise 2-octet ASNs
          #
          if rfc4893_updates:
            path_seg_val.append(str(struct.unpack_from(">L",
                                                       update,
                                                       offset2)[0]))
            offset2 += 4
          else:
            path_seg_val.append(str(struct.unpack_from(">H",
                                                       update,
                                                       offset2)[0]))
            offset2 += 2

        path_seg_str = " ".join(path_seg_val)
        print_msg.append(BGP.AS_PATH_SEG_FORMAT[path_seg_type] % path_seg_str)
        print_msg.append("\n")

    # next hop
    #
    elif attr_type_code == BGP.ATTR_TYPE_NEXT_HOP:
      next_hop = update[offset:offset + 4]
      print_msg.append(indent + BGP.ATTR_TYPE_STR[attr_type_code] + " ")
      print_msg.append(socket.inet_ntoa(next_hop) + "\n")

    # MED
    #
    elif attr_type_code == BGP.ATTR_TYPE_MULTI_EXIT_DISC:
      print_msg.append(indent + BGP.ATTR_TYPE_STR[attr_type_code] + " ")
      attr_val = struct.unpack_from(">L", update, offset)[0]
      print_msg.append(str(attr_val) + "\n")

    # communities
    #
    elif attr_type_code == BGP.ATTR_TYPE_COMMUNITIES:
      print_msg.append(indent + BGP.ATTR_TYPE_STR[attr_type_code] + " ")

      # make a local copy of offset
      #
      offset2 = offset

      # walk through the community values
      #
      comm_val = []
      while offset2 < (offset + attr_len):
        x = struct.unpack_from(">L", update, offset2)[0]

        # if a well-known community, use its name; else re-unpack for 
        # presentation
        #
        if x in BGP.WELL_KNOWN_COMM:
          comm_val.append(BGP.WELL_KNOWN_COMM[x])
        else:
          high, low = struct.unpack_from(">HH", update, offset2)
          comm_val.append(str(high) + ":" + str(low))
        offset2 += 4
      print_msg.append(" ".join(comm_val) + "\n")

    # mp_reach
    #
    elif attr_type_code == BGP.ATTR_TYPE_MP_REACH_NLRI:
      print_msg.append(indent + BGP.ATTR_TYPE_STR[attr_type_code] + "\n")
      print_msg.append(indent + "length " + str(attr_len) +
                       " at " + str(offset) + "\n")

      offset2 = offset

      # afi, safi, nhl
      #
      afi, safi, nhl = struct.unpack_from(">HBB", update, offset2)
      offset2 += 4

      # next hop
      #
      socket_afi = 0
      if afi == BGP.AF_IP:
        socket_afi = socket.AF_INET
        next_hop = socket.inet_ntop(socket.AF_INET, update[offset2:offset2+4])
      elif afi == BGP.AF_IP6:
        socket_afi = socket.AF_INET6
        next_hop = socket.inet_ntop(socket.AF_INET6,
                                    update[offset2:offset2+16])
      else:
        next_hop = "unknown for afi %d" % afi
      print_msg.append(indent + "NEXT_HOP " + next_hop + "\n")
      if safi == 1:
        print_msg.append(indent + "AFI %d SAFI unicast\n" % afi)
      elif safi == 2:
        print_msg.append(indent + "AFI %d SAFI multicast\n" % afi)
      elif safi == 3:
        print_msg.append(indent + "AFI %d SAFI unicast+multicast\n" % afi)
      else:
        print_msg.append(indent + "AFI %d SAFI %d\n" % afi, safi)

      offset2 += nhl

      # number of SNPAs
      #
      num_snpa = struct.unpack_from(">B", update, offset2)[0]
      offset2 += 1

      # dump the snpas
      #
      for x in range(num_snpa):

        # get the length
        #
        snpa_len = struct.unpack_from(">B", update, offset2)[0]
        offset2 += 1

        # you have to read RFC2858 to believe this
        #
        snpa_len_octets = snpa_len / 2
        if snpa_len % 2:
          snpa_len_octets += 1
        snpa_dump = []
        for y in range(snpa_len_octets):
          snpa_dump.append("0x%x" % struct.unpack_from(">B",
                                                       update,
                                                       offset2 + y))
        print_msg.append(indent + "SNPA " + str(x) + " " +
                         "".join(snpa_dump))
        offset2 += snpa_len_octets

      # next section is nlri information, parse and add to print_msg
      #
      if verbose:
        print_msg.append(indent +
                         "NLRI portion of " +
                         BGP.ATTR_TYPE_STR[attr_type_code] +
                         " at " +
                         str(offset2) +
                         "\n")
      nlri_text = ParseBgpNlri(update,
                               offset2,
                               offset + attr_len,
                               afi,
                               verbose)
      if nlri_text:
        prepend_str = indent + "mp_nlri "
        sep = "\n" + prepend_str
        print_msg.append(prepend_str + sep.join(nlri_text) + "\n")

    # mp_unreach
    #
    elif attr_type_code == BGP.ATTR_TYPE_MP_UNREACH_NLRI:
      print_msg.append(indent + BGP.ATTR_TYPE_STR[attr_type_code] + "\n")
      print_msg.append(indent + "length " + str(attr_len) + " at " +
                       str(offset) + "\n")

      offset2 = offset

      # afi, safi
      #
      afi, safi = struct.unpack_from(">HBB", update, offset2)
      offset2 += 2

      # figure out what to say
      #
      socket_afi = 0
      next_hop = ""
      if afi == BGP.AF_IP:
        socket_afi = socket.AF_INET
        print_msg.append(indent + "mp_unreach_nlri for %d" % socket_afi)
      elif afi == BGP.AF_IP6:
        socket_afi = socket.AF_INET6
        print_msg.append(indent + "mp_unreach_nlri for %d" % socket_afi)
      else:
        print_msg.append(indent + "mp_unreach unknown for afi %d" % afi)

    # catch-all
    #
    elif attr_type_code in BGP.ATTR_TYPE_STR:
      print_msg.append(indent + BGP.ATTR_TYPE_STR[attr_type_code] + "\n")

    # adjust pointers
    #
    offset += attr_len

  # next section is nlri information, parse and add to print_msg
  #
  if verbose:
    print_msg.append(indent + "NLRI portion of update at %d\n" % offset)
  nlri_text = ParseBgpNlri(update, offset, length, BGP.AF_IP, verbose)
  if nlri_text:
    prepend_str = indent + "nlri "
    sep = "\n" + prepend_str
    print_msg.append(prepend_str + sep.join(nlri_text) + "\n")

  # print the message
  #
  print("".join(print_msg)),


# function to collect bytes from a stream socket *or* a file
#
def CollectBytes(s, l):
  """Collect bytes from a socket or file.

  Args:
    s: socket from which to read.
    l: number of bytes to read.

  Returns:
    a buffer containing the requested number of bytes
  """

  global RECORD_SESSION

  # if it's a socket, do this
  #
  if type(s) == socket.SocketType:

    # read 'l' bytes from the socket into the right sized buffer
    #
    buf = array.array("B", [0] * l)
    remain = l

    while remain:
      count = s.recv_into(buf, remain)
      remain -= count

      # maybe write to the recording session
      #
      if RECORD_SESSION != 0:
        RECORD_SESSION.write(buf)
        RECORD_SESSION.flush()

  else:
    string_val = s.read(l)
    if len(string_val) < l:
      s.close()
      sys.exit(0)
    buf = array.array("B", [0] * l)
    for x in range(l):
      struct.pack_into("B",
                       buf,
                       x,
                       struct.unpack_from("B", string_val, x)[0])

  return buf


# parse BGP nlri information
#
def ParseBgpNlri(update, start, end, afi, verbose=0):
  """Parse BGP NLRI into readable text.

  Args:
    update: a buffer containing a BGP message.
    start: offset at which NLRI parsing is to start.
    end: offset at which NLRI parsing is to stop.
    afi: address family, per RFC1700.
    verbose: be chatty, or not.

  Returns:
    a list of strings
  """

  global DEBUG_FLAG

  nlri_text = []
  offset2 = start

  try:
    while offset2 < end:

      # get prefix length, and figure out how much we need to take from
      # update to represent it
      #
      prefix_len = update[offset2]
      need_bytes = BGP.BytesForPrefix(prefix_len)

      # advance pointer
      #
      offset2 += 1

      # maybe override afi
      #
      if (need_bytes > 4) and (afi == BGP.AF_IP):
        if verbose:
          print "WARNING: overriding AFI due to bytes needed for prefix length"
        afi = BGP.AF_IP6

      # get a buffer of correct size for address family
      #
      if afi == BGP.AF_IP:
        socket_afi = socket.AF_INET
        prefix = array.array("B", [0] * 4)
      elif afi == BGP.AF_IP6:
        socket_afi = socket.AF_INET6
        prefix = array.array("B", [0] * 16)
      else:
        assert False, "don't know what to do with AFI %d" % afi

      # copy from update into buffer and advance pointer
      #
      for x in range(need_bytes):
        prefix[x] = update[x + offset2]
      offset2 += need_bytes

      # convert to presentation
      #
      nlri_text.append(socket.inet_ntop(socket_afi, prefix) +
                       "/" +
                       str(prefix_len))

  except IndexError:
    nlri_text.append("parse error at %d" % offset2)
    if DEBUG_FLAG:
      raise IndexError("parse error at %d" % offset2)

  return nlri_text


# usage
#
def Usage():
  """Print usage information.

  Args:
    none.

  Returns:
    nothing
  """

  print """
Usage: bmpreceiver.py [-d | --debug]
                      [-v | --verbose]
                      [-4 | --rfc4893]
                      [-f file | --file=file]
                      [-p port | --port=port]
Options:
  -d      : print debug messages
  -v      : print verbose messages
  -4      : RFC4893-style BGP updates
  -f file : if port > 0, record BMP messages to file
          : if port = 0, read BMP messages from file
  -p port : if port > 0, port on which to listen for a BMP connection
          : if port = 0, read BMP messages from file specified in -f
"""


# main
#
def main(argv):
  global RECORD_SESSION
  global DEBUG_FLAG

  # command-line arguments
  #
  try:
    opts, args = getopt.getopt(argv,
                               "dv4p:f:",
                               ["debug",
                                "verbose",
                                "rfc4893",
                                "port=",
                                "file="])
  except getopt.GetoptError:
    Usage()
    sys.exit(2)

  if args:
    Usage()
    sys.exit(2)

  port = PORT
  rfc4893_updates = 0
  verbose_flag = 0
  record_file = ""
  for o, a in opts:
    if o in ("-p", "--port"):
      port = int(a)
    elif o in ("-f", "--file"):
      record_file = a
    elif o in ("-4", "--rfc4893"):
      rfc4893_updates = 1
    elif o in ("-d", "--debug"):
      DEBUG_FLAG += 1
    elif o in ("-v", "--verbose"):
      verbose_flag = 1
    else:
      assert False, "unhandled option"

  # if recording, open the file for writes
  #
  if port and record_file:
    try:
      RECORD_SESSION = open(record_file, "wb")
    except Exception:
      raise Exception("error opening % for write" % record_file)
  else:
    RECORD_SESSION = 0

  # if port is non-zero open a listening socket, wait for a connection
  #
  if port != 0:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((HOST, port))
    listener.listen(1)

  while 1:

    # if port is non-zero, we got a connection, accept it
    #
    if port != 0:
      conn, addr = listener.accept()
      print "Connection from", addr
    else:
      conn = open(record_file, "rb", 0)
      print "Reading from " + record_file

    while 1:
      # read a header
      #
      msg_type = CollectBmpHeader(conn, verbose_flag)

      # Route Monitoring message
      # draft-ietf-grow-bmp-01.txt section 2.1
      #
      if msg_type == BMP.MSG_TYPE_ROUTE_MONITORING:
        CollectBgpUpdate(conn, rfc4893_updates, verbose_flag)

      # Statistics Report
      # draft-ietf-grow-bmp-01.txt section 2.2
      #
      elif msg_type == BMP.MSG_TYPE_STATISTICS_REPORT:
        CollectBmpSrMsg(conn, verbose_flag)

      # Peer Down message
      # draft-ietf-grow-bmp-01.txt section 2.3
      #
      elif msg_type == BMP.MSG_TYPE_PEER_DOWN_NOTIFICATION:
        CollectBmpPeerDown(conn, verbose_flag)

      # else we don't know the type, we can't parse any more
      #
      else:
        assert False, "unknown BMP message type"


if __name__ == "__main__":
  try:
    main(sys.argv[1:])
  finally:
    if RECORD_SESSION != 0:
      RECORD_SESSION.close()
