
# Jeti ExBus High Level Analyzer (EXBUS-HLA)
# Copyright 2024, Markus Pfaff
# For more information and documentation, please go to https://support.saleae.com/extensions/high-level-analyzer-extensions

# ToDo
# The information returned to the calling low level analyzer by
#   return AnalyzerFrame('Pkt', frame.start_time, frame.end_time, {'l': self.tag_str})
# was not used as intended by Saleae insofar as the data structure at the end of the
# statement is a python dictionary
# This enables statements like this:
#   return AnalyzerFrame('Pkt', frame.start_time, frame.end_time, {
#      'l': self.some_length_str, 'wisdom': self.some_wisdom_str, 'truth': self.some_truth_str})
# This populates the data table in the Saleae Logic2 window with the according columns
# where the header of a column is the dictionary key string.


import enum
from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting, NumberSetting, ChoicesSetting

# High level analyzers must subclass the HighLevelAnalyzer class.
class Hla(HighLevelAnalyzer):
 
    result_types = {
        'exbus_start_sync_byte': {
            'format': 'Start sync byte'
        },
        'exbus_analog_ReadDataAsInt': {
            'format': 'ReadDataAsInt: {{data.ReadDataAsInt}}'
        },
        'exbus_digital_ReadDataAsInt': {
            'format': 'ReadDataAsInt: {{data.ReadDataAsInt}}'
        },
        'exbus_end_sync_byte': {
            'format': 'End sync byte'
        }
    }

    # Decoder FSM
    class dec_fsm_e(enum.Enum):
        idle = 1
        master_start_byte_rcvd = 2
        slave_start_byte_rcvd = 3
        packet_length_byte = 4
        id_byte = 5
        data_identifyer_byte = 6
        data_block_len_byte = 7
        decoding_block = 8
        packet_crc_lsb = 9
        packet_crc_msb = 10
        analog_ReadDataAsInt = 20
        digital_ReadDataAsInt = 21

    class packet_type_e(enum.Enum):
        channel_value_packet = 1
        telemetry_packet = 2
        jetibox_packet = 3
        unknown_packet = 4

    class extlm_dec_fsm_e(enum.Enum):
        extlm_idle = 1
        extlm_first_data_byte = 2
        extlm_first_data_consumed = 3

    class extlm_packet_type_e(enum.Enum):
        extlm_type_text = 0
        extlm_type_data = 1
        extlm_type_message = 2

  
    # Protocol defines for master frames
    EXBUS_START_BYTE_MSTR_CH_DATA = b'\x3e'
    EXBUS_START_BYTE_MSTR_TLM_REQ = b'\x3d'
    EXBUS_REQ_RESP = b'\x01'
    EXBUS_RESP = b'\x01'
    EXBUS_NO_RESP = b'\x03'

    # Protocol defines for slave frames
    EXBUS_START_BYTE_SLV_TLM_RSP = b'\x3b'   
    EXBUS_START_BYTE_SLV_UNKNOWN1_RSP = b'\x3c'   

    # Protocol data identifiers
    EXBUS_CHANNEL_VALUES = b'\x31'
    EXBUS_TELEMETRY = b'\x3A'
    EXBUS_JETIBOX = b'\x3B'
    EXBUS_UNKNOWN1 = b'\x50'
 
    # EX telemetry sub packet identifiers
    EXTLM_START_BYTE = 0x0f
    EXTLM_START_BYTE_POS = 1
    EXTLM_PKT_TYPE_AND_LENGTH_POS = 2
    EXTLM_PKT_TYPE_TEXT = 0b00
    EXTLM_PKT_TYPE_DATA = 0b01
    EXTLM_PKT_TYPE_MESSAGE = 0b10
    EXTLM_MANUFACTURER_ID_POS = 3
    EXTLM_DEVICE_ID_POS = 5
    EXTLM_RESERVED_BYTE_POS = 7
    EXTLM_FIRST_ENTRY_POS = 8
    EXTLM_DATA_TYPE_6b = 0
    EXTLM_DATA_TYPE_6b_LEN = 1
    EXTLM_DATA_TYPE_14b = 1
    EXTLM_DATA_TYPE_14b_LEN = 2
    EXTLM_DATA_TYPE_22b = 4
    EXTLM_DATA_TYPE_22b_LEN = 3
    EXTLM_DATA_TYPE_TIMEDATE = 5
    EXTLM_DATA_TYPE_TIMEDATE_LEN = 3
    EXTLM_DATA_TYPE_30b = 8
    EXTLM_DATA_TYPE_30b_LEN = 4
    EXTLM_DATA_TYPE_GPS = 9
    EXTLM_DATA_TYPE_GPS_LEN = 4


    exbus_STOP_SYNC_BYTE = b'\x00'  # 0x00

    def __init__(self):

        # Initialize HLA.
        self.tag_str = ('') # String to decorate the tags above the waveform in Saleae Logic2
        self.exbus_frame_start = None  # Timestamp: Start of frame
        self.exbus_frame_end = None  # Timestamp: End of frame
        self.dec_fsm = self.dec_fsm_e.idle  # Current state of protocol decoder FSM
        self.packet_type = self.packet_type_e.channel_value_packet
        self.exbus_packet_length = 0 # Length of overall packet in nr of bytes
        self.exbus_frame_current_index = 0  # Index to determine end of ReadDataAsInt
        self.extlm_dec_fsm = self.extlm_dec_fsm_e.extlm_idle # We need an FSM to decide where we are in decoding extlm
        self.extlm_packet_length = 0 # Length of the EX telemtry packet content
        self.extlm_type = self.extlm_packet_type_e.extlm_type_text # The kind of data is transported in EX sub packet
        self.exbus_channel_value = 0  # Stores the channel data for a single channel
        self.exbus_channel_ids = 0 # index to current channel
        self.extlm_entry_idx = 0 # The index used for a single data entry (1 to 4 bytes)
        self.extlm_entry_id = 0 # ID of the sensor value
        self.extlm_entry_length = 0 # Number of bytes for a single data entry (1 to 4 bytes)
        self.extlm_description_length = 0 # Length of sensor value description string
        self.extlm_unit_length = 0 # Length of sensor value description string
        self.exbus_block_length = 0 # length of the block currently under decoding
        self.exbus_block_byte_idx = 0 # Index onto current data byte in block
        self.exbus_block_start = None  # Timestamp: Start of block
        self.exbus_block_end = None  # Timestamp: End of block
        print("Initialized EXBUS HLA.")

        # Settings can be accessed using the same name used above.

        #print("Settings:", self.my_string_setting,
        #      self.my_number_setting, self.my_choices_setting)

    def decode(self, frame: AnalyzerFrame):
        '''
        Process a frame from the input analyzer, and optionally return a single `AnalyzerFrame` or a list of `AnalyzerFrame`s.

        The type and data values in `frame` will depend on the input analyzer.
        '''
        ReadDataAsInt = int.from_bytes(frame.data['data'], byteorder='big')

        # New frame
        if self.exbus_frame_start == None and self.dec_fsm == self.dec_fsm_e.idle:
            self.exbus_frame_current_index = 0
            if frame.data['data'] == self.EXBUS_START_BYTE_MSTR_CH_DATA:
                print('')
                print('Master: Start channel data frame detected at', frame.start_time)
                self.exbus_frame_start = frame.start_time
                self.dec_fsm = self.dec_fsm_e.master_start_byte_rcvd
                self.exbus_frame_current_index += 1
                return AnalyzerFrame('Mstr:ChData', frame.start_time, frame.end_time, {})
            elif frame.data['data'] == self.EXBUS_START_BYTE_MSTR_TLM_REQ:
                print('Master: Start telemetry request frame at', frame.start_time)
                self.exbus_frame_start = frame.start_time
                self.dec_fsm = self.dec_fsm_e.master_start_byte_rcvd
                self.exbus_frame_current_index += 1
                return AnalyzerFrame('Mstr:Tlm?', frame.start_time, frame.end_time, {})
            elif frame.data['data'] == self.EXBUS_START_BYTE_SLV_TLM_RSP:
                print('Slave: Telemetry reponse at', frame.start_time)
                self.exbus_frame_start = frame.start_time
                self.dec_fsm = self.dec_fsm_e.slave_start_byte_rcvd
                self.exbus_frame_current_index += 1
                return AnalyzerFrame('Slv:Rsp', frame.start_time, frame.end_time, {})
            elif frame.data['data'] == self.EXBUS_START_BYTE_SLV_UNKNOWN1_RSP:
                print('Slave: Unknown response at', frame.start_time)
                self.exbus_frame_start = frame.start_time
                self.dec_fsm = self.dec_fsm_e.slave_start_byte_rcvd
                self.exbus_frame_current_index += 1
                return AnalyzerFrame('Slv:UnknRsp', frame.start_time, frame.end_time, {})

        if self.dec_fsm == self.dec_fsm_e.master_start_byte_rcvd:
            if frame.data['data'] == self.EXBUS_REQ_RESP:
                #print('Master: Slave should response.')
                self.dec_fsm = self.dec_fsm_e.packet_length_byte
                self.exbus_frame_current_index += 1
                return AnalyzerFrame('Mstr:ReqResp', frame.start_time, frame.end_time, {})
            elif frame.data['data'] == self.EXBUS_NO_RESP:
                #print('Master: Slave, do not response!')
                self.dec_fsm = self.dec_fsm_e.packet_length_byte
                self.exbus_frame_current_index += 1
                return AnalyzerFrame('Mstr:NoResp', frame.start_time, frame.end_time, {})
        elif self.dec_fsm == self.dec_fsm_e.slave_start_byte_rcvd:
            if frame.data['data'] == self.EXBUS_RESP:
                #print('Slave response.')
                self.dec_fsm = self.dec_fsm_e.packet_length_byte
                self.exbus_frame_current_index += 1
                return AnalyzerFrame('Slv:Resp', frame.start_time, frame.end_time, {})

        if self.dec_fsm == self.dec_fsm_e.packet_length_byte:
           #print('Packet length byte read.')
           self.tag_str = ('{}').format(ReadDataAsInt)
           self.exbus_packet_length = int.from_bytes(frame.data['data'], byteorder='big')
           self.dec_fsm = self.dec_fsm_e.id_byte
           self.exbus_frame_current_index += 1
           return AnalyzerFrame('Pkt', frame.start_time, frame.end_time, {'l': self.tag_str})

        if self.dec_fsm == self.dec_fsm_e.id_byte:
           self.tag_str = ('{}').format(ReadDataAsInt)
           #print('Packet ID byte read.')
           self.dec_fsm = self.dec_fsm_e.data_identifyer_byte
           self.exbus_frame_current_index += 1
           return AnalyzerFrame('PktID', frame.start_time, frame.end_time, {'': self.tag_str})

        if self.dec_fsm == self.dec_fsm_e.data_identifyer_byte:
           self.dec_fsm = self.dec_fsm_e.data_block_len_byte
           self.exbus_frame_current_index += 1
           if frame.data['data'] == self.EXBUS_CHANNEL_VALUES: 
              #print('Packet contains channel values.')
              self.packet_type = self.packet_type_e.channel_value_packet
              return AnalyzerFrame('Chan', frame.start_time, frame.end_time, {'':'Channel packet'})
           elif frame.data['data'] == self.EXBUS_TELEMETRY: 
              #print('Telemetry req or response.')
              self.packet_type = self.packet_type_e.telemetry_packet
              return AnalyzerFrame('Tlm', frame.start_time, frame.end_time, {'':'Telemetry packet'})
           elif frame.data['data'] == self.EXBUS_TELEMETRY: 
              #print('JetiBox key values or response string.')
              self.packet_type = self.packet_type_e.jetibox_packet
              return AnalyzerFrame('JetiBx', frame.start_time, frame.end_time, {'':'JetiBox packet'})
           else:
              #print('Unknown data block starts.')
              self.packet_type = self.packet_type_e.unknown_packet
              return AnalyzerFrame('???', frame.start_time, frame.end_time, {'':'Unknown packet format'})

        if self.dec_fsm == self.dec_fsm_e.data_block_len_byte:
           #print('Block length read.')
           self.exbus_frame_current_index += 1
           self.exbus_block_byte_idx = 0
           self.exbus_block_length = int.from_bytes(frame.data['data'], byteorder='big')
           self.tag_str = ('{}').format(self.exbus_block_length)
           # ExBus definition contains the flaw that the CRC postion cannot be detected
           # without length information which can only be verified by CRC. 
           if self.exbus_packet_length-2 == self.exbus_frame_current_index:
              self.dec_fsm = self.dec_fsm_e.packet_crc_lsb
           else:
              self.dec_fsm = self.dec_fsm_e.decoding_block
           return AnalyzerFrame('Blk', frame.start_time, frame.end_time, {'': self.tag_str})   

        if self.dec_fsm == self.dec_fsm_e.decoding_block:
           self.exbus_frame_current_index += 1
           if self.exbus_block_byte_idx == 0:
              self.exbus_block_start = frame.start_time
              self.exbus_channel_idx = 1
              self.tag_str = ('')
           self.exbus_block_byte_idx += 1

           if self.packet_type == self.packet_type_e.channel_value_packet:
              if self.exbus_block_byte_idx < self.exbus_block_length:
                 # Here comes the channel data from the transmitter.
                 if self.exbus_block_byte_idx%2 != 0:
                    # LSB of channel
                    self.exbus_channel_value = ReadDataAsInt
                 else:
                    # MSB of channel
                    # combine both and multiply by 1/8 us
                    self.exbus_channel_value = (ReadDataAsInt * 256 + self.exbus_channel_value) / 8
                    self.tag_str += ('Ch{}:{}us, ').format(self.exbus_channel_idx, round(self.exbus_channel_value))
                    self.exbus_channel_idx += 1
              else: 
                 if self.exbus_frame_current_index == self.exbus_packet_length - 2:
                    self.dec_fsm = self.dec_fsm_e.packet_crc_lsb
                 else:
                    self.dec_fsm = self.dec_fsm_e.data_identifyer_byte
                 return AnalyzerFrame('ChnData', self.exbus_block_start, frame.end_time, {'l': self.tag_str})
              
           elif self.packet_type == self.packet_type_e.telemetry_packet:
              # This is the region in which EX telemetry packets travel as sub-packets
              # in the ExBus packet 
               if self.exbus_block_byte_idx <= self.exbus_block_length:
                 #print('Processing EX telemetry sub packet')
                 #print(hex(ReadDataAsInt))
                 #print(self.exbus_block_byte_idx, self.exbus_block_length)
                 if self.exbus_block_byte_idx == self.EXTLM_START_BYTE_POS and ReadDataAsInt&0x0F == self.EXTLM_START_BYTE:
                    return AnalyzerFrame('ExTlm Startbyte', frame.start_time, frame.end_time, {})
                 elif self.exbus_block_byte_idx == self.EXTLM_PKT_TYPE_AND_LENGTH_POS:
                    self.tag_str = ('')
                    self.extlm_packet_length = ReadDataAsInt&0b00111111
                    #print(self.extlm_packet_length)
                    if ReadDataAsInt>>6 == self.EXTLM_PKT_TYPE_TEXT:
                       #print('EX text telemetry packet encountered')
                       self.extlm_type = self.extlm_packet_type_e.extlm_type_text
                       self.tag_str = ('{}').format(self.extlm_packet_length)
                       return AnalyzerFrame('TxtPkt', frame.start_time, frame.end_time, {'l': self.tag_str})
                    elif ReadDataAsInt>>6 == self.EXTLM_PKT_TYPE_DATA:
                       #print('EX data telemetry packet encountered')
                       self.extlm_type = self.extlm_packet_type_e.extlm_type_data
                       self.tag_str = ('{}').format(self.extlm_packet_length)
                       return AnalyzerFrame('DataPkt', frame.start_time, frame.end_time, {'l': self.tag_str})
                    elif ReadDataAsInt>>6 == self.EXTLM_PKT_TYPE_MESSAGE:
                       #print('EX message telemetry packet encountered')
                       self.extlm_type = self.extlm_packet_type_e.extlm_type_message
                       self.tag_str = ('{}').format(self.extlm_packet_length)
                       return AnalyzerFrame('MsgPkt', frame.start_time, frame.end_time, {'l': self.tag_str})
                    else:
                       #print('EX message telemetry packet encountered')
                       self.extlm_type = self.extlm_packet_type_e.extlm_type_message
                       self.tag_str = ('{}').format(self.extlm_packet_length)
                       return AnalyzerFrame('UnknownPkt', frame.start_time, frame.end_time, {'l': self.tag_str})
               
                    
                 elif self.exbus_block_byte_idx == self.EXTLM_MANUFACTURER_ID_POS:
                    self.exbus_block_start = frame.start_time
                 elif self.exbus_block_byte_idx == self.EXTLM_MANUFACTURER_ID_POS+1:
                    return AnalyzerFrame('MfctID', self.exbus_block_start, frame.end_time, {})
                 elif self.exbus_block_byte_idx == self.EXTLM_DEVICE_ID_POS:
                    self.exbus_block_start = frame.start_time
                 elif self.exbus_block_byte_idx == self.EXTLM_DEVICE_ID_POS+1:
                    return AnalyzerFrame('DeviceID', self.exbus_block_start, frame.end_time, {})
                 elif self.exbus_block_byte_idx == self.EXTLM_RESERVED_BYTE_POS:
                    # Prepare for the first data entry
                    self.extlm_dec_fsm = self.extlm_dec_fsm_e.extlm_first_data_byte
                    self.extlm_entry_idx = 0
                    return AnalyzerFrame('Reserved', frame.start_time, frame.end_time, {})
                 elif self.exbus_block_byte_idx >= self.EXTLM_FIRST_ENTRY_POS and self.exbus_block_byte_idx < self.exbus_block_length:
                    self.extlm_entry_idx += 1
                    if self.extlm_type == self.extlm_packet_type_e.extlm_type_data:
                       if self.extlm_entry_idx == 1:
                          self.exbus_block_start = frame.start_time
                          self.extlm_entry_id = ReadDataAsInt>>4
                          # telemetry entry length is one extra byte added to the data bytes (the Id/Type byte)
                          if ReadDataAsInt&0b00001111 == self.EXTLM_DATA_TYPE_6b:
                             self.extlm_entry_length = self.EXTLM_DATA_TYPE_6b_LEN+1
                          elif ReadDataAsInt&0b00001111 == self.EXTLM_DATA_TYPE_14b:
                             self.extlm_entry_length = self.EXTLM_DATA_TYPE_14b_LEN+1
                          elif ReadDataAsInt&0b00001111 == self.EXTLM_DATA_TYPE_22b:
                             self.extlm_entry_length = self.EXTLM_DATA_TYPE_22b_LEN+1
                          elif ReadDataAsInt&0b00001111 == self.EXTLM_DATA_TYPE_TIMEDATE:
                             self.extlm_entry_length = self.EXTLM_DATA_TYPE_TIMEDATE_LEN+1
                          elif ReadDataAsInt&0b00001111 == self.EXTLM_DATA_TYPE_30b:
                             self.extlm_entry_length = self.EXTLM_DATA_TYPE_30b_LEN+1
                          elif ReadDataAsInt&0b00001111 == self.EXTLM_DATA_TYPE_GPS:
                             self.extlm_entry_length = self.EXTLM_DATA_TYPE_GPS_LEN+1
                          else:
                             #print('Unkown data type encountered in EX telemetry data entry')
                             pass
                          if self.extlm_entry_id == 0:
                             # Special telemetry id 0 means the id is encoded in next byte
                             # Thus this entry has an extra byte
                             self.extlm_entry_length += 1
                          else:
                             # ID in [1..15]
                             # Subtract ID/type byte from length
                             self.tag_str = ('ID:{}, type:{}, len:{}').format(self.extlm_entry_id,ReadDataAsInt&0b00001111, self.extlm_entry_length-1)
                          #print (self.tag_str)
                       elif self.extlm_entry_idx == 2 and self.extlm_entry_id == 0:
                          # In this special case this is the byte the id es encoded in
                          self.extlm_entry_id = ReadDataAsInt
                          # Subtract 2 ID/type bytes from length
                          self.tag_str = ('ID:{}, type:{}, len:{}').format(self.extlm_entry_id,ReadDataAsInt&0b00001111, self.extlm_entry_length-2)
                          #print (self.tag_str)
                       elif self.extlm_entry_idx == self.extlm_entry_length:
                          # Last byte of data entry
                          self.extlm_entry_idx = 0
                          return AnalyzerFrame('', self.exbus_block_start, frame.end_time, {'Data': self.tag_str})
                       else:
                          # one of the middle bytes of data entry
                          return None
                       
                    elif self.extlm_type == self.extlm_packet_type_e.extlm_type_text:
                       if self.extlm_entry_idx == 1:
                          self.exbus_block_start = frame.start_time
                          self.extlm_entry_id = ReadDataAsInt
                       elif self.extlm_entry_idx == 2:
                          self.extlm_description_length = ReadDataAsInt>>3
                          self.extlm_unit_length = ReadDataAsInt&0b00000111
                          #print('Text entry encountered')
                          self.tag_str = ('ID:{}, lenDescr:{}, lenUnit:{}').format(self.extlm_entry_id,self.extlm_description_length, self.extlm_unit_length)
                          #print (self.tag_str)
                       else:
                          try:
                             self.tag_str += str(frame.data['data'], encoding = 'utf-8')
                          except:
                             self.tag_str += '?'
                          if self.extlm_entry_idx == 2 + self.extlm_description_length + self.extlm_unit_length:
                             # Last byte of data entry
                             self.extlm_entry_idx = 0
                             return AnalyzerFrame('', self.exbus_block_start, frame.end_time, {'Description': self.tag_str})
                          else:
                             # one of the middle bytes of data entry
                             return None
                    elif self.extlm_type == self.extlm_packet_type_e.extlm_type_message:
                       # !!! Message packages are currently not decoded
                       # Add this if needed
                       return None
                    else:
                       return None
                    
                 elif self.exbus_block_byte_idx == self.exbus_block_length:
                    # Last byte of this block
                    if self.exbus_frame_current_index == self.exbus_packet_length - 2:
                       self.dec_fsm = self.dec_fsm_e.packet_crc_lsb
                    else:
                       self.dec_fsm = self.dec_fsm_e.data_identifyer_byte
                    return AnalyzerFrame('ExTlmCrc8', frame.start_time, frame.end_time, {})

           elif self.packet_type == self.packet_type_e.jetibox_packet:
              if self.exbus_block_byte_idx < self.exbus_block_length:
                 #print('Further JetiBox data)
                 pass
              else: 
                 if self.exbus_frame_current_index == self.exbus_packet_length - 2:
                    self.dec_fsm = self.dec_fsm_e.packet_crc_lsb
                 else:
                    self.dec_fsm = self.dec_fsm_e.data_identifyer_byte
                 return AnalyzerFrame('JetiBox', self.exbus_block_start, frame.end_time, {})

           elif self.packet_type == self.packet_type_e.unknown_packet:
              if self.exbus_block_byte_idx < self.exbus_block_length:
                 #print('Further unknown type data)
                 pass
              else: 
                 if self.exbus_frame_current_index == self.exbus_packet_length - 2:
                    self.dec_fsm = self.dec_fsm_e.packet_crc_lsb
                 else:
                    self.dec_fsm = self.dec_fsm_e.data_identifyer_byte
                 return AnalyzerFrame('UnknownData', self.exbus_block_start, frame.end_time, {})

           else:
              self.dec_fsm = self.dec_fsm_e.idle
              self.exbus_frame_start = None
              return AnalyzerFrame('ExtendHLA!', frame.start_time, frame.end_time, {})

        if self.dec_fsm == self.dec_fsm_e.packet_crc_lsb:
           #print('Packet CRC LSB.')
           self.exbus_block_start = frame.start_time
           self.dec_fsm = self.dec_fsm_e.packet_crc_msb
           self.exbus_frame_current_index += 1
           return None

        if self.dec_fsm == self.dec_fsm_e.packet_crc_msb:
           self.exbus_frame_current_index += 1
           #print('Packet CRC MSB.')
           #print(self.exbus_packet_length, self.exbus_frame_current_index)
           self.dec_fsm = self.dec_fsm_e.idle
           self.exbus_frame_start = None
           #print(self.exbus_frame_current_index, self.exbus_packet_length)
           if self.exbus_frame_current_index == self.exbus_packet_length:
              return AnalyzerFrame('PktCrc', self.exbus_block_start, frame.end_time, {})
           else:
              return AnalyzerFrame('PktLenErr!', frame.start_time, frame.end_time, {})               
