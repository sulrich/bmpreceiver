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

"""
BGP (Border Gateway Protocol)

Various constants associated with the protocol
"""
__version__ = '4.0'

HEADER_LEN = 19

# message types
#
OPEN = 1
UPDATE = 2
NOTIFICATION = 3
KEEPALIVE = 4
MSG_TYPE_STR = {OPEN: 'OPEN',
                UPDATE: 'UPDATE',
                NOTIFICATION: 'NOTIFICATION',
                KEEPALIVE: 'KEEPALIVE'}

# attribute types
#
ATTR_TYPE_ORIGIN = 1
ATTR_TYPE_AS_PATH = 2
ATTR_TYPE_NEXT_HOP = 3
ATTR_TYPE_MULTI_EXIT_DISC = 4
ATTR_TYPE_LOCAL_PREF = 5
ATTR_TYPE_ATOMIC_AGGREGATE = 6
ATTR_TYPE_AGGEGATOR = 7
ATTR_TYPE_COMMUNITIES = 8
ATTR_TYPE_ORIGINATOR_ID = 9
ATTR_TYPE_CLUSTER_LIST = 10
ATTR_TYPE_DPA = 11
ATTR_TYPE_ADVERTISER = 12
ATTR_TYPE_RCID_PATH = 13
ATTR_TYPE_MP_REACH_NLRI = 14
ATTR_TYPE_MP_UNREACH_NLRI = 15
ATTR_TYPE_AS4_PATH = 17
ATTR_TYPE_AS4_AGGREGATOR = 18

ATTR_TYPE_STR = {ATTR_TYPE_ORIGIN: 'ORIGIN', 
                 ATTR_TYPE_AS_PATH: 'AS_PATH', 
                 ATTR_TYPE_NEXT_HOP: 'NEXT_HOP', 
                 ATTR_TYPE_MULTI_EXIT_DISC: 'MULTI_EXIT_DISC', 
                 ATTR_TYPE_LOCAL_PREF: 'LOCAL_PREF', 
                 ATTR_TYPE_ATOMIC_AGGREGATE: 'ATOMIC_AGGREGATE', 
                 ATTR_TYPE_AGGEGATOR: 'AGGREGATOR', 
                 ATTR_TYPE_COMMUNITIES: 'COMMUNITIES',
                 ATTR_TYPE_ORIGINATOR_ID: 'ORIGINATOR_ID',
                 ATTR_TYPE_CLUSTER_LIST: 'CLUSTER_LIST',
                 ATTR_TYPE_DPA: 'DPA',
                 ATTR_TYPE_ADVERTISER: 'ADVERTISER',
                 ATTR_TYPE_RCID_PATH: 'RCID_PATH',
                 ATTR_TYPE_MP_REACH_NLRI: 'MP_REACH_NLRI',
                 ATTR_TYPE_MP_UNREACH_NLRI: 'MP_UNREACH_NLRI',
                 ATTR_TYPE_AS4_PATH: 'AS4_PATH',
                 ATTR_TYPE_AS4_AGGREGATOR: 'AS4_AGGREGATOR',
                 }

# attribute flag values
#
ATTR_FLAG_OPTIONAL = 128
ATTR_FLAG_TRANSITIVE = 64
ATTR_FLAG_PARTIAL = 32
ATTR_FLAG_EXT_LEN = 16

# ORIGIN values
#
ORIGIN_IGP = 0
ORIGIN_EGP = 1
ORIGIN_INCOMPLETE = 2
ORIGIN_STR = {ORIGIN_IGP: 'IGP', 
              ORIGIN_EGP: 'EGP', 
              ORIGIN_INCOMPLETE: 'incomplete'}

# AS_PATH path segment type codes
#
AS_SET = 1
AS_SEQUENCE = 2
AS_CONFED_SET = 3
AS_CONFED_SEQUENCE = 4
AS_PATH_SEG_STR = {AS_SET: 'set', 
                   AS_SEQUENCE: 'sequence', 
                   AS_CONFED_SET: 'confed_set', 
                   AS_CONFED_SEQUENCE: 'confed_seq'}
AS_PATH_SEG_FORMAT = {AS_SET: '{ %s }',
                      AS_SEQUENCE: '%s', 
                      AS_CONFED_SET: '( %s )', 
                      AS_CONFED_SEQUENCE: '( %s )'}

# NOTIFICATION codes
#
MESSAGE_HEADER_ERROR = 1
OPEN_MESSAGE_ERROR = 2
UPDATE_MESSAGE_ERROR = 3
HOLD_TIMER_EXPIRED = 4
FINITE_STATE_MACHINE_ERROR = 5
CEASE = 6
NOTIFICATION_STR = {MESSAGE_HEADER_ERROR: 'MESSAGE_HEADER_ERROR',
                    OPEN_MESSAGE_ERROR: 'OPEN_MESSAGE_ERROR',
                    UPDATE_MESSAGE_ERROR: 'UPDATE_MESSAGE_ERROR',
                    HOLD_TIMER_EXPIRED: 'HOLD_TIMER_EXPIRED',
                    FINITE_STATE_MACHINE_ERROR: 'FINITE_STATE_MACHINE_ERROR',
                    CEASE: 'CEASE'}

# well-known communities
#
WELL_KNOWN_COMM = {0xFFFFFF01: 'NO_EXPORT',
                   0xFFFFFF02: 'NO_ADVERTISE',
                   0xFFFFFF03: 'NO_EXPORT_SUBCONFED'}

# address families
#
AF_IP = 1
AF_IP6 = 2

# function to determine the number of bytes necessary to represent a
# prefix of length 'len' per RFC4271
#
def bytes_for_prefix(len):
  if (len <= 8):
    return 1
  elif (len <= 16):
    return 2
  elif (len <= 24):
    return 3
  elif (len <= 32):
    return 4
  elif (len <= 40):
    return 5
  elif (len <= 48):
    return 6
  elif (len <= 56):
    return 7
  elif (len <= 64):
    return 8
  elif (len <= 72):
    return 9
  elif (len <= 80):
    return 10
  elif (len <= 88):
    return 11
  elif (len <= 96):
    return 12
  elif (len <= 104):
    return 13
  elif (len <= 112):
    return 14
  elif (len <= 120):
    return 15
  elif (len <= 128):
    return 16
  assert(len <= 128)
