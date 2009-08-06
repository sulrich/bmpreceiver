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

__author__ = "sstuart@google.com (Stephen Stuart)"

import sys
import getopt
import struct
import array
import socket
import time
import string
import BGP
import BMP

# constants
#
HOST = ''
PORT = 0

# global variables
#
RecordSession = 0
DebugFlag = 0

# function to collect a BMP header
#
def collect_bmp_header(s, verbose=0):

  print_msg = []

  # read the fixed-length header from the socket
  #
  header = collect_bytes(s, BMP.HEADER_LEN)

  # unpack and decide what to print
  #
  version, msg_type, peer_type, peer_flags = struct.unpack('>BBBB', header[0:4])
  print_msg.append('BMP version ' + str(version))
  print_msg.append(' msg_type ' + BMP.MSG_TYPE_STR[msg_type])
  if verbose:
    print_msg.append(' peer_type ' + BMP.PEER_TYPE_STR[peer_type])
    print_msg.append(" peer_flags 0x%x\n" % peer_flags)
  else:
    print_msg.append("\n")
  if ((peer_flags & BMP.PEER_FLAG_IPV6) == BMP.PEER_FLAG_IPV6):
    peer_address = socket.inet_ntop(socket.AF_INET6, header[12:28])
  else:
    peer_address = socket.inet_ntop(socket.AF_INET, header[24:28])
  if verbose:
    print_msg.append('  peer_address ' + peer_address)
    peer_as, peer_bgp_id, time_sec, time_usec = struct.unpack(">LLLL", header[28:44])
    print_msg.append(' as ' + str(peer_as))
    print_msg.append(' router_id ' + socket.inet_ntoa(header[32:36]) + "\n")
    print_msg.append('  time ' + time.ctime(time_sec) + "\n")

  # print the message 
  #
  print string.join(print_msg, ''),

  # if we have a version mismatch, we're pretty much done here
  #
  assert (version == BMP.VERSION), "BMP version mismatch"

  # return the message type so the caller can decide what to do next
  #
  return msg_type


# function to collect a BMP peer down notification
#
def collect_bmp_peer_down(s, verbose=0):

  indent = ' ' * 2

  reason_code = collect_bytes(s, 1)
  if (reason_code[0] == 1):
    print indent + "Local system closed session, notification sent"
    collect_bgp_notification(s)
  elif (reason_code[0] == 2):
    print indent + "Local system closed session, no notification"
  elif (reason_code[0] == 3):
    print indent + "Remote system closed session, notification sent"
    collect_bgp_notification(s)
  elif (reason_code[0] == 4):
    print indent + "Remote system closed session, no notification"
  else:
    assert False, "unknown Peer Down reason code"


# function to collect a BMP statistics report
#
def collect_bmp_sr_msg(s, verbose=0):

  print_msg = []
  indent = ' ' * 2

  # find out many TLVs there are
  #
  stats_count_buf = collect_bytes(s, 4)
  stats_count = struct.unpack('>L', stats_count_buf)[0]
  print_msg.append(indent + str(stats_count) + " TLVs present\n")
  
  # read all the TLVs
  #
  for x in range(stats_count):
    stat_type_len_buf = collect_bytes(s, 4)
    stat_type, stat_len = struct.unpack('>HH', stat_type_len_buf)
    stat_data_buf = collect_bytes(s, stat_len)
    # print 'BMP SR type ' + str(stat_type) + ' len ' + str(stat_len)
    if (stat_type in BMP.SR_TYPE_STR):
      assert(stat_len == 4)
      stat_val = struct.unpack('>L', stat_data_buf)[0]
      if verbose:
        print_msg.append(indent + indent + str(stat_val) + ' ')
        print_msg.append(BMP.SR_TYPE_STR[stat_type] + "\n")

  # print the message
  #
  print string.join(print_msg, ''),


# function to collect the header of a BGP PDU
# RFC4271 section 4.1
#
def collect_bgp_header(s, verbose=0):

  indent = ' ' * 2
  
  # get the header
  #
  header = collect_bytes(s, BGP.HEADER_LEN);

  try:

    # verify that the marker is correct
    #
    for x in range(0, 15): assert (header[x] == 255)
    
    # unpack the length and type
    #
    length, type = struct.unpack('>HB', header[16:19]);
    print indent + 'BGP ' + BGP.MSG_TYPE_STR[type],
    if verbose:
      print "length %d" % (length - BGP.HEADER_LEN)
    else:
      print
    
    # return the length of the rest of the PDU, and its type
    #
    return length - BGP.HEADER_LEN, type

  except:
    hex_dump = [];
    for x in range(BGP.HEADER_LEN):
      hex_dump.append('0x%x' % struct.unpack('B', header[x]))
    print string.join(hex_dump)
    raise


# function to collect a BGP notification PDU
# RFC4271 section 4.5
#
def collect_bgp_notification(s, verbose=0):

  print_msg = [];
  indent = ' ' * 4

  # get the header
  #
  length, type = collect_bgp_header(s)
  assert(type == BGP.NOTIFICATION)

  # get the rest of the PDU
  #
  notification = collect_bytes(s, length);
  code, subcode = struct.unpack('>BB', notification[0:2])
  print_msg.append(indent + 'NOTIFICATION code ' + str(code) + ' subcode ' + str(subcode) + "\n")

  # if there are data bytes, dump them in hex
  #
  if ((length > 2) and verbose):
    print_msg.append(indent + 'NOTIFICATION data ')
    for x in range(3, length - 1): print_msg.append(" 0x%x" % update[x])
    print_msg.append("\n")

  # print the message
  #
  print string.join(print_msg, ''),


# function to collect a BGP update PDU
# RFC1997
# RFC2858
# RFC4271 section 4.3
# RFC4893
#
def collect_bgp_update(s, verbose=0):

  print_msg = []
  indent = ' ' * 4

  # get the header
  #
  length, type = collect_bgp_header(s, verbose)
  assert (type == BGP.UPDATE)

  # get the rest of the PDU
  #
  update = collect_bytes(s, length);

  # start parsing at offset 0
  #
  offset = 0

  # next section is withdrawn routes
  #
  withdrawn_route_len = struct.unpack_from('>H', update[0:2], offset)[0]
  if verbose:
    print indent + 'withdrawn at ' + str(offset) + ' length ' + str(withdrawn_route_len)
  offset += 2
  if withdrawn_route_len:
    withdrawn_text = parse_bgp_nlri(update, 
                                    offset, 
                                    offset + withdrawn_route_len,
                                    BGP.AF_IP,
                                    verbose)
    if (len(withdrawn_text)):
      prepend_str = indent + 'withdraw '
      print_msg.append(prepend_str + 
                       string.join(withdrawn_text, "\n" + prepend_str) + 
                       "\n")

    offset += withdrawn_route_len

  # next section is path attributes
  #
  path_attr_len = struct.unpack_from('>H', update, offset)[0]
  if verbose:
    print indent + 'path atributes at ' + str(offset) + ' length ' + str(path_attr_len)
  offset += 2
  path_attr_end = offset + path_attr_len
  while (offset < path_attr_end):

    # get flags and type code
    #
    attr_flags, attr_type_code = struct.unpack_from('>BB', update, offset)
    if verbose:
      print_msg.append(indent + 
                       'path attr ' +
                       BGP.ATTR_TYPE_STR[attr_type_code] + 
                       ' at ' +
                       str(offset))
      print_msg.append(' flags 0x%x (' % attr_flags)
      attr_list = []
      if ((attr_flags & BGP.ATTR_FLAG_OPTIONAL) == BGP.ATTR_FLAG_OPTIONAL):
        attr_list.append('optional')
      if ((attr_flags & BGP.ATTR_FLAG_TRANSITIVE) == BGP.ATTR_FLAG_TRANSITIVE):
        attr_list.append('transitive')
      if ((attr_flags & BGP.ATTR_FLAG_PARTIAL) == BGP.ATTR_FLAG_PARTIAL):
        attr_list.append('partial')
      if ((attr_flags & BGP.ATTR_FLAG_EXT_LEN) == BGP.ATTR_FLAG_EXT_LEN):
        attr_list.append('extended-length')
      print_msg.append(string.join(attr_list))
    offset += 2

    # check for extended length
    #
    if ((attr_flags & BGP.ATTR_FLAG_EXT_LEN) == BGP.ATTR_FLAG_EXT_LEN):
      attr_len = struct.unpack_from('>H', update, offset)[0]
      offset += 2
    else:
      attr_len = update[offset]
      offset += 1

    if verbose:
      print_msg.append(")\n")

    # origin
    #
    if (attr_type_code == BGP.ATTR_TYPE_ORIGIN):
      assert(attr_len == 1, 'attr_len wrong')
      print_msg.append(indent + BGP.ATTR_TYPE_STR[attr_type_code] + ' ')
      print_msg.append(BGP.ORIGIN_STR[update[offset]])
      print_msg.append("\n")

    # AS path
    #
    elif (attr_type_code == BGP.ATTR_TYPE_AS_PATH):
      print_msg.append(indent + BGP.ATTR_TYPE_STR[attr_type_code] + ' ')
      
      # make a local copy of offset
      #
      offset2 = offset

      # walk through the path segments; BMP constructs updates that 
      # conform to RFC4893 (ASNs are 4 octets)
      #
      while (offset2 < offset + attr_len):
        path_seg_type = update[offset2]
        offset2 += 1
        path_seg_len = update[offset2]
        offset2 += 1
        path_seg_val = [];
        for x in range(path_seg_len):
          path_seg_val.append(str(struct.unpack_from('>L', update, offset2)[0]))
          offset2 += 4
        path_seg_str = string.join(path_seg_val, ' ')
        print_msg.append(BGP.AS_PATH_SEG_FORMAT[path_seg_type] % path_seg_str)
        print_msg.append("\n")

    # next hop
    #
    elif (attr_type_code == BGP.ATTR_TYPE_NEXT_HOP):
      next_hop = update[offset:offset + 4]
      print_msg.append(indent + BGP.ATTR_TYPE_STR[attr_type_code] + ' ')
      print_msg.append(socket.inet_ntoa(next_hop) + "\n")

    # MED
    #
    elif (attr_type_code == BGP.ATTR_TYPE_MULTI_EXIT_DISC):
      print_msg.append(indent + BGP.ATTR_TYPE_STR[attr_type_code] + ' ')
      attr_val = struct.unpack_from('>L', update, offset)[0]
      print_msg.append(str(attr_val) + "\n")

    # communities
    #
    elif (attr_type_code == BGP.ATTR_TYPE_COMMUNITIES):
      print_msg.append(indent + BGP.ATTR_TYPE_STR[attr_type_code] + ' ')
      
      # make a local copy of offset
      #
      offset2 = offset

      # walk through the community values
      #
      comm_val = []
      while (offset2 < offset + attr_len):
        x = struct.unpack_from('>L', update, offset2)[0]

        # if a well-known community, use its name; else re-unpack for 
        # presentation
        #
        if x in BGP.WELL_KNOWN_COMM:
          comm_val.append(BGP.WELL_KNOWN_COMM[x])
        else:
          high, low = struct.unpack_from('>HH', update, offset2)
          comm_val.append(str(high) + ':' + str(low))
        offset2 += 4
      print_msg.append(string.join(comm_val) + "\n")

    # mp_reach
    #
    elif (attr_type_code == BGP.ATTR_TYPE_MP_REACH_NLRI):
      print_msg.append(indent + BGP.ATTR_TYPE_STR[attr_type_code] + "\n")
      print_msg.append(indent + 'length ' + str(attr_len) + " at " + str(offset) + "\n")

      offset2 = offset

      # afi, safi, nhl
      #
      afi, safi, nhl = struct.unpack_from('>HBB', update, offset2)
      offset2 += 4

      # next hop
      #
      socket_afi = 0
      if (afi == BGP.AF_IP):
        socket_afi = socket.AF_INET
        next_hop = socket.inet_ntop(socket.AF_INET, update[offset2:offset2+4])
      elif (afi == BGP.AF_IP6):
        socket_afi = socket.AF_INET6
        next_hop = socket.inet_ntop(socket.AF_INET6, 
                                    update[offset2:offset2+16])
      else:
        next_hop = 'unknown for afi %d' % afi
      print_msg.append(indent + 'NEXT_HOP ' + next_hop + "\n")
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
      num_snpa = struct.unpack_from('>B', update, offset2)[0]
      offset2 += 1
      
      # dump the snpas
      #
      for x in range(num_snpa):

        # get the length
        #
        snpa_len = struct.unpack_from('>B', update, offset2)[0]
        offset2 += 1

        # you have to read RFC2858 to believe this
        #
        snpa_len_octets = snpa_len / 2
        if (snpa_len % 2): 
          snpa_len_ocets += 1
        snpa_dump = [];
        for y in range(snpa_len_ocets):
          snpa_dump.append('0x%x' % struct.unpack_from('>B',
                                                       update,
                                                       offset2 + y));
        print_msg.append(indent + 'SNPA ' + str(x) + ' ' + string.join(snpa_dump, ''))
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
      nlri_text = parse_bgp_nlri(update, 
                                 offset2, 
                                 offset + attr_len, 
                                 afi, 
                                 verbose)
      if len(nlri_text):
        prepend_str = indent + 'mp_nlri '
        print_msg.append(prepend_str +
                         string.join(nlri_text, "\n" + prepend_str) + 
                         "\n")
                         
    # mp_unreach
    #
    elif (attr_type_code == BGP.ATTR_TYPE_MP_UNREACH_NLRI):
      print_msg.append(indent + BGP.ATTR_TYPE_STR[attr_type_code] + "\n")
      print_msg.append(indent + 'length ' + str(attr_len) + " at " + str(offset) + "\n")

      offset2 = offset

      # afi, safi
      #
      afi, safi = struct.unpack_from('>HBB', update, offset2)
      offset2 += 2

      # figure out what to say
      #
      socket_afi = 0
      if (afi == BGP.AF_IP):
        print_msg.append
        socket_afi = socket.AF_INET
      elif (afi == BGP.AF_IP6):
        socket_afi = socket.AF_INET6
      else:
        next_hop = 'unknown for afi %d' % afi

    # catch-all
    #
    elif (attr_type_code in BGP.ATTR_TYPE_STR):
      print_msg.append(indent + BGP.ATTR_TYPE_STR[attr_type_code] + "\n")
      
    # adjust pointers
    #
    offset += attr_len

  # next section is nlri information, parse and add to print_msg
  #
  if verbose:
    print_msg.append(indent + "NLRI portion of update at %d\n" % offset)
  nlri_text = parse_bgp_nlri(update, offset, length, BGP.AF_IP, verbose)
  if len(nlri_text):
    prepend_str = indent + 'nlri '
    print_msg.append(prepend_str + 
                     string.join(nlri_text, "\n" + prepend_str) + 
                     "\n")

  # print the message
  #                   
  print(string.join(print_msg, '')),


# function to collect bytes from a stream socket *or* a file
#
def collect_bytes(s, l):
  global RecordSession

  # if it's a socket, do this
  #
  if type(s) == socket.SocketType:

    # read 'l' bytes from the socket into the right sized buffer
    #
    buffer = array.array('B', [0] * l)
    remain = l
    
    while (remain):
      count = s.recv_into(buffer, remain)
      remain -= count
      
      # maybe write to the recording session
      #
      if RecordSession != 0:
        RecordSession.write(buffer)
        RecordSession.flush()
  
  else:
    string_val = s.read(l)
    if (len(string_val) < l):
      s.close()
      sys.exit(0)
    buffer = array.array('B', [0] * l)
    for x in range(l):
      struct.pack_into('B', 
                       buffer, 
                       x, 
                       struct.unpack_from('B', string_val, x)[0])

  return buffer


# parse BGP nlri information
#
def parse_bgp_nlri(update, start, end, afi, verbose = 0):
  global DebugFlag
  
  nlri_text = []
  offset2 = start

  try: 
    while (offset2 < end):

      # get prefix length, and figure out how much we need to take from
      # update to represent it
      #
      prefix_len = update[offset2]
      need_bytes = BGP.bytes_for_prefix(prefix_len)

      # advance pointer
      #
      offset2 += 1

      # maybe override afi
      #
#      if (need_bytes > 4) and (afi == BGP.AF_IP): 
#        print "WARNING: overriding AFI due to bytes needed for prefix length"
#        afi = BGP.AF_IP6

      # get a buffer of correct size for address family
      #
      if (afi == BGP.AF_IP):
        socket_afi = socket.AF_INET
        prefix = array.array('B', [0] * 4)
      elif (afi == BGP.AF_IP6):
        socket_afi = socket.AF_INET6
        prefix = array.array('B', [0] * 16)
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

  except:
    nlri_text.append("parse error at %d" % offset2)
    if DebugFlag:
      raise

  return nlri_text
  

# usage
#
def usage():
  print """
Usage: print-bmp.py [-d | --debug]
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
  global RecordSession
  global DebugFlag

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
    usage()
    sys.exit(2)
  port = PORT

  rfc4893_updates = 0;
  verbose_flag = 0
  record_file = '';
  for o, a in opts :
    if o in ('-p', '--port'):
      port = int(a)
    elif o in ('-f', '--file'):
      record_file = a
    elif o in ('-4', '--rfc4893'):
      rfc4893_updates = 1
    elif o in ('-d', '--debug'):
      DebugFlag += 1
    elif o in ('-v', '--verbose'):
      verbose_flag = 1
    else:
      assert False, "unhandled option"

  # if recording, open the file for writes
  #
  if port != 0 and record_file != '':
    try:
      RecordSession = open(record_file, 'wb')
    except:
      raise
  else:
    RecordSession = 0

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
      print 'Connection from', addr
    else:
      conn = open(record_file, 'rb', 0)
      print 'Reading from ' + record_file
    
    while 1:
      # read a header
      #
      msg_type = collect_bmp_header(conn, verbose_flag)

      # Route Monitoring message
      # draft-ietf-grow-bmp-01.txt section 2.1
      #
      if (msg_type == BMP.MSG_TYPE_ROUTE_MONITORING):
        collect_bgp_update(conn, verbose_flag)
        
      # Statistics Report
      # draft-ietf-grow-bmp-01.txt section 2.2
      #
      elif (msg_type == BMP.MSG_TYPE_STATISTICS_REPORT):
        collect_bmp_sr_msg(conn, verbose_flag)

      # Peer Down message
      # draft-ietf-grow-bmp-01.txt section 2.3
      #
      elif (msg_type == BMP.MSG_TYPE_PEER_DOWN_NOTIFICATION):
        collect_bmp_peer_down(conn, verbose_flag)

      # else we don't know the type, we can't parse any more
      #
      else:
        assert False, "unknown BMP message type"

if __name__ == "__main__":
  try:
    main(sys.argv[1:])
  except:
    if RecordSession != 0:
      RecordSession.close()
    raise
