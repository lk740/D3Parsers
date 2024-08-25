# File: dofus.py
# description : a Scapy dissector for Dofus protocol
# Installation on Linux/Windows : copy the file into the scapy contrib folder
# Requirement : google protobuf package
# Author : lk740
from scapy.modules.p0fv2 import pkt2uptime
from scapy.packet import Packet, bind_layers
from scapy.layers.inet import TCP
from scapy.fields import (
    Field,
    FieldLenField,
    PacketLenField,
    MultipleTypeField,
    StrLenField,
    ConditionalField, ByteEnumField,
)

from google.protobuf.internal.decoder import _DecodeVarint
import struct

DOFUS_WIRE_TYPES = {
    0: "VARINT",
    1: "I64",
    2: "LEN",
    3: "SGROUP",
    4: "EGROUP",
    5: "I32"
}

DOFUS_MESSAGES = {
    1: "Request",
    2: "Response",
    3: "Event",
}

DOFUS_REQUEST_PARAM_TYPES = {
    0: "uuid",
    1: "ping",
    2: "identification",
    3: "selectServer",
    4: "forceAccount",
    5: "releaseAccount",
    6: "characters_request",
    7: "friend_list_request",
    8: "acquaintance_servers_request",
}

DOFUS_CHAT_CHANNEL_TYPES = {
    0: "GLOBAL",
    1: "TEAM",
    2: "GUILDE",
    3: "ALLIANCE",
    4: "PARTY",
    5: "SALES",
    6: "SEEK",
    7: "NOOB",
    8: "ADMIN",
    9: "ARENA",
    10: "PRIVATE",
    11: "INFO",
    12: "FIGHT_LOG",
    13: "ADS",
    14: "EVENT",
    15: "EXCHANGE",
}

class PbTLVField(Field):
    def __init__(self, name, default):
        Field.__init__(self, name, default, fmt="B")

    def i2repr(self, pkt, x):
        if x is None:
            return x

        if isinstance(x, bytes):
            x = int.from_bytes(x, byteorder="big")

        id = (x | 0b111) >> 3
        wtype = x & 0b111
        return f"wtype: {DOFUS_WIRE_TYPES[wtype]}, id: {id}  (0x{(x.to_bytes((x.bit_length() // 7) + 1, 'big')).hex()})"


    def get_varint(self, s):
        result = 0
        pos = 0
        for i in range(0, 64, 7):
            b = int.from_bytes(s[pos:pos + 1], "big")
            result += (b & 0b01111111) << i
            if not b & 0b10000000:
                # self.sz = (result.bit_length() // 7) + 1
                return result
            pos += 1
        raise Exception("Too much data")

    def set_varint(self, pkt, val):
        val = self.i2m(pkt, val)
        result = b""
        assert val.bit_length() <= 64
        while val:
            b = val & 0b01111111
            val >>= 7
            if val:
                b |= 0b10000000
            result += b.to_bytes(1, "big")
        return result

    def getfield(self, pkt, s):  # type: (Packet, bytes) -> Tuple[bytes, I]
        result = 0
        pos = 0
        for i in range(0, 64, 7):
            b = int.from_bytes(s[pos:pos + 1], "big")
            result += (b & 0b01111111) << i
            if not b & 0b10000000:
                #self.sz = (result.bit_length() // 7) + 1
                wtype = result & 0b111
                if wtype == 2:  # descriptor
                    return s[pos+1:], result
                if wtype == 0:  # varint
                    return s[pos+1:], result
                if wtype == 1:
                    return s[8:], self.m2i(pkt, s[:8])
                if wtype == 5:
                    return s[4:], self.m2i(pkt, s[:4])
                raise Exception("Invalid wire type")
            pos += 1
        raise Exception("Too much data")


    def addfield(self, pkt, s, val):  # type: (Packet, bytes, Optional[I]) -> bytes
        wtype = self.i2m(pkt, val) & 0b111

        if wtype == 2:
            result = self.set_varint(pkt, val)
            return s + result
        if wtype == 0:
            result = self.set_varint(pkt, val)
            return s + result
        if wtype == 0:
            return struct.pack("!%is"%8, self.i2m(pkt, val)) + s
        if wtype == 5:
            return struct.pack("!%is" % 5, self.i2m(pkt, val)) + s
        raise Exception("Invalid wire type")


class PbLenField(FieldLenField):

    def __init__(self, name, default, length_of=None, count_of=None, adjust=lambda pkt, x: x):
        super(PbLenField, self).__init__(name, default, length_of, "B", count_of, adjust)

    def addfield(self, pkt, s, val):  # type: (Packet, bytes, Optional[I]) -> bytes
        val = self.i2m(pkt, val)
        result = b""
        assert val.bit_length() <= 64
        while val:
            b = val & 0b01111111
            val >>= 7
            if val:
                b |= 0b10000000
            result += b.to_bytes(1, "big")
        return s + result

    def getfield(self, pkt, s):  # type: (Packet, bytes) -> Tuple[bytes, I]
        result = 0
        pos = 0
        for i in range(0, 64, 7):
            b = int.from_bytes(s[pos:pos + 1], "big")
            result += (b & 0b01111111) << i
            if not b & 0b10000000:
                self.sz = (result.bit_length() // 7) + 1
                return s[pos + 1:], result
            pos += 1
        raise Exception("Too much data")

class PbVarIntField(Field):
    def __init__(self, name, default):
        super(PbVarIntField, self).__init__(name, default, fmt="B")

    def addfield(self, pkt, s, val):  # type: (Packet, bytes, Optional[I]) -> bytes
        val = self.i2m(pkt, val)
        result = b""
        assert val.bit_length() <= 64
        while val:
            b = val & 0b01111111
            val >>= 7
            if val:
                b |= 0b10000000
            result += b.to_bytes(1, "big")
        return s + result

    def getfield(self, pkt, s):  # type: (Packet, bytes) -> Tuple[bytes, I]
        result = 0
        pos = 0
        for i in range(0, 64, 7):
            b = int.from_bytes(s[pos:pos + 1], "big")
            result += (b & 0b01111111) << i
            if not b & 0b10000000:
                self.sz = (result.bit_length() // 7) + 1
                return s[pos + 1:], result
            pos += 1
        raise Exception("Too much data")


def extract_wtype(v):
    """
    Retrieve wire type in Protobuf TLV value
    """
    if isinstance(v, bytes):
        v = int.from_bytes(v, "big")
    return (v & 0b111)

def extract_field_id(v):
    """
    Retrieve field id in Protobuf TLV value
    """
    if isinstance(v, bytes):
        v = int.from_bytes(v, "big")
    return (v | 0b111) >> 3

class GameProtoConnPingRequest(Packet):
    fields_desc = [
        PbTLVField("tlv", 0x08),
        PbVarIntField("quiet", 1),
    ]

class GameProtoConnPongEvent(Packet):
    fields_desc = [
        PbTLVField("tlv", 0x08),
        PbVarIntField("quiet", 1),
    ]

class GameProtoCharCharacterExperienceGainEvent(Packet):
    fields_desc = [
        PbTLVField("tlv", 0x08),
        ConditionalField(PbVarIntField("characterExperience", 1), lambda pkt: extract_field_id(pkt.tlv) == 1),
        ConditionalField(PbVarIntField("mountExperience", 1), lambda pkt: extract_field_id(pkt.tlv) == 2),
        ConditionalField(PbVarIntField("guildExperience", 1), lambda pkt: extract_field_id(pkt.tlv) == 3),
    ]

class GameProtoCharCharacterLevelUpEvent(Packet):
    fields_desc = [
        PbTLVField("tlv", 0x08),
        PbVarIntField("newLevel", 1),
    ]

class GameProtoInvKamasUpdateEvent(Packet):
    fields_desc = [
        PbTLVField("tlv", 0x08),
        PbVarIntField("quantity", 1),
    ]

class GameProtoChatChatChannelMessageRequest(Packet):
    fields_desc = [
        PbTLVField("tlvContent", 0x0a),
        PbLenField("lenContent", None, length_of="content"),
        StrLenField("content", b"hi !", length_from=lambda pkt: pkt.lenContent),
        PbTLVField("tlvChannel", 0x10),
        ByteEnumField("channel", 0, DOFUS_CHAT_CHANNEL_TYPES),
        # Object field missing
    ]

class ConnProtoMessReqContent(Packet):
    fields_desc = [
        PbTLVField("tlvFunc", 0x0a),
        PbLenField("lenFunc", None, length_of="function"),
        StrLenField("function", b"type.ankama.com/com.ankama.dofus.server.game.protocol.connection.PingRequest", length_from=lambda pkt: pkt.lenFunc),
        PbTLVField("tlvData", 0x12),
        PbLenField("lenData", None, length_of="data"),
        MultipleTypeField(
            [
                    (
                        PacketLenField(
                            "data",
                            GameProtoConnPingRequest(),
                            GameProtoConnPingRequest,
                            length_from=lambda pkt: pkt.lenData,
                        ),
                        lambda pkt: pkt.function == b"type.ankama.com/com.ankama.dofus.server.game.protocol.connection.PingRequest",
                    ),
                    (
                        PacketLenField(
                            "data",
                            GameProtoChatChatChannelMessageRequest(),
                            GameProtoChatChatChannelMessageRequest,
                            length_from=lambda pkt: pkt.lenData,
                        ),
                        lambda
                            pkt: pkt.function == b"type.ankama.com/com.ankama.dofus.server.game.protocol.chat.ChatChannelMessageRequest",
                    ),
                ],
            StrLenField(
                "data",
                "not implemented",
                length_from=lambda pkt: pkt.lenData,
            ),
        ),
    ]

class ConnProtoMessRespContent(Packet):
    fields_desc = [
        PbTLVField("tlv", 0x0a),
        PbLenField("len", None, length_of="function"),
        StrLenField("function", b"type.ankama.com/com.ankama.dofus.server.game.protocol.connection.PingRequest", length_from=lambda pkt: pkt.len),
    ]

class ConnProtoMessEvtContent(Packet):
    fields_desc = [
        PbTLVField("tlvFunc", 0x0a),
        PbLenField("lenFunc", None, length_of="function"),
        StrLenField("function", b"type.ankama.com/com.ankama.dofus.server.game.protocol.connection.PongEvent", length_from=lambda pkt: pkt.lenFunc),
        PbTLVField("tlvData", 0x12),
        PbLenField("lenData", None, length_of="data"),
        MultipleTypeField(
            [
                (
                    PacketLenField(
                        "data",
                        GameProtoConnPongEvent(),
                        GameProtoConnPongEvent,
                        length_from=lambda pkt: pkt.lenData,
                    ),
                    lambda pkt: pkt.function == b"type.ankama.com/com.ankama.dofus.server.game.protocol.connection.PongEvent",
                ),
                (
                    PacketLenField(
                        "data",
                        GameProtoCharCharacterExperienceGainEvent(),
                        GameProtoCharCharacterExperienceGainEvent,
                        length_from=lambda pkt: pkt.lenData,
                    ),
                    lambda
                        pkt: pkt.function == b"type.ankama.com/com.ankama.dofus.server.game.protocol.character.CharacterExperienceGainEvent",
                ),
                (
                    PacketLenField(
                        "data",
                        GameProtoCharCharacterLevelUpEvent(),
                        GameProtoCharCharacterLevelUpEvent,
                        length_from=lambda pkt: pkt.lenData,
                    ),
                    lambda
                        pkt: pkt.function == b"type.ankama.com/com.ankama.dofus.server.game.protocol.character.CharacterLevelUpEvent",
                ),
                (
                    PacketLenField(
                        "data",
                        GameProtoInvKamasUpdateEvent(),
                        GameProtoInvKamasUpdateEvent,
                        length_from=lambda pkt: pkt.lenData,
                    ),
                    lambda
                        pkt: pkt.function == b"type.ankama.com/com.ankama.dofus.server.game.protocol.inventory.KamasUpdateEvent",
                ),
            ],
            StrLenField(
                "data",
                "not implemented",
                length_from=lambda pkt: pkt.lenData,
            ),
        ),
    ]

class ConnProtoMessRequest(Packet):
    fields_desc = [
        PbTLVField("tlvUid", 0x08),
        PbVarIntField("uid", 1),
        PbTLVField("tlvContent", 0x12),
        PbLenField("len", None, length_of="content"),
        PacketLenField("content", ConnProtoMessReqContent(), ConnProtoMessReqContent, length_from=lambda pkt: pkt.len),
    ]

class ConnProtoMessResponse(Packet):
    fields_desc = [
        PbTLVField("tlvUid", 0x08),
        PbVarIntField("uid", 1),
        PbTLVField("tlvContent", 0x12),
        PbLenField("len", None, length_of="content"),
        PacketLenField("content", ConnProtoMessRespContent(), ConnProtoMessRespContent, length_from=lambda pkt: pkt.len),
    ]

class ConnProtoMessEvent(Packet):
    fields_desc = [
        PbTLVField("tlv", 0x0a),
        PbLenField("len", None, length_of="content"),
        PacketLenField("content", ConnProtoMessEvtContent(), ConnProtoMessEvtContent, length_from=lambda pkt: pkt.len),
    ]

class ConnProtoMessage(Packet):
    fields_desc = [
        PbTLVField("tlv", 0x0a),
        PbLenField("len", None, length_of="type"),
        MultipleTypeField(
            [
                (
                    PacketLenField(
                        "type",
                        ConnProtoMessRequest(),
                        ConnProtoMessRequest,
                        length_from=lambda pkt: pkt.len,
                    ),
                    lambda pkt: extract_field_id(pkt.tlv) == 1 , # if field id is equal to 1
                ),
                (
                    PacketLenField(
                        "type",
                        ConnProtoMessResponse(),
                        ConnProtoMessResponse,
                        length_from=lambda pkt: pkt.len,
                    ),
                    lambda pkt: extract_field_id(pkt.tlv) == 2,  # if field id is equal to 2
                ),
                (
                    PacketLenField(
                        "type",
                        ConnProtoMessEvent(),
                        ConnProtoMessEvent,
                        length_from=lambda pkt: pkt.len,
                    ),
                    lambda pkt: extract_field_id(pkt.tlv) == 3,  # if field id is equal to 3
                ),
            ],
            StrLenField(
                "type",
                "not implemented",
                length_from=lambda pkt: pkt.len,
            )
        ),
    ]


class DofusRequest(Packet):
    name = "DofusRequest"
    fields_desc = [
        PbLenField("len", None, length_of="message"),
        PacketLenField("message", ConnProtoMessage() , ConnProtoMessage, length_from=lambda pkt: pkt.len),
    ]

    @classmethod
    def tcp_reassemble(cls, data, metadata, session):
        bytes_consumed = 0
        while bytes_consumed < len(data):

            ## Get packet length
            length, pos = _DecodeVarint(data, 0)
            length += len(data[:pos])

            if length == len(data):
                bytes_consumed += length
                return cls(data)

            ## Need more data
            elif length > len(data):
                return None

            ## If there are several dofus data in the packet
            elif length < len(data):
                bytes_consumed += length
                bind_layers(DofusResponse, DofusResponse)  ## Build a new layer

            else:
                raise NotImplementedError("Unsupported data length")

        ## Return the dissected packet when there are several Dofus layer
        return cls(data[:bytes_consumed])


class DofusResponse(Packet):
    name = "DofusResponse"
    fields_desc = [
        PbLenField("length", None, length_of="message"),
        PacketLenField("message", ConnProtoMessage() , ConnProtoMessage, length_from=lambda pkt: pkt.length),
    ]

    @classmethod
    def tcp_reassemble(cls, data, metadata, session):

        bytes_consumed = 0
        while bytes_consumed < len(data):

            ## Get packet length
            length, pos = _DecodeVarint(data, 0)
            length += len(data[:pos])

            if length == len(data):
                bytes_consumed += length
                return cls(data)

            ## Need more data
            elif length > len(data):
                return None

            ## If there are several dofus data in the packet
            elif length < len(data):
                bytes_consumed += length
                bind_layers(DofusResponse, DofusResponse)  ## Build a new layer

            else:
                raise NotImplementedError("Unsupported data length")

        ## Return the dissected packet when there are several Dofus layer
        return cls(data[:bytes_consumed])

bind_layers(TCP, DofusRequest, dport=5555)
bind_layers(TCP, DofusResponse, sport=5555)