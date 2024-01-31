
# Jeti ExBus High Level Analyzer (EXBUS-HLA)
# Copyright 2024, Markus Pfaff
# For more information and documentation, please go to https://support.saleae.com/extensions/high-level-analyzer-extensions

import enum
from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting, NumberSetting, ChoicesSetting


# High level analyzers must subclass the HighLevelAnalyzer class.
class Hla(HighLevelAnalyzer):
 
    result_types = {
        'exbus_start_sync_byte': {
            'format': 'Start sync byte'
        },
        'exbus_analog_payload': {
            'format': 'PAYLOAD: {{data.payload}}'
        },
        'exbus_digital_payload': {
            'format': 'PAYLOAD: {{data.payload}}'
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
        analog_payload = 20
        digital_payload = 21

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
    EXTLM_PKG_TYPE_AND_LENGTH_POS = 2
    EXTLM_PKG_TYPE_TEXT = 0b00
    EXTLM_PKG_TYPE_DATA = 0b01
    EXTLM_PKG_TYPE_MESSAGE = 0b10
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
        # String to decorate the tags above the waveform in Saleae Logic2
        self.tag_str = ('')
        self.exbus_frame_start = None  # Timestamp: Start of frame
        self.exbus_frame_end = None  # Timestamp: End of frame
        self.dec_fsm = self.dec_fsm_e.idle  # Current state of protocol decoder FSM
        self.packet_type = self.packet_type_e.channel_value_packet
        self.exbus_packet_length = 0 # Length of overall packet in nr of bytes
        self.exbus_frame_current_index = 0  # Index to determine end of payload
        self.extlm_dec_fsm = self.extlm_dec_fsm_e.extlm_idle # We need an FSM to decide where we are in decoding extlm
        self.extlm_packet_length = 0 # Length of the EX telemtry packet content
        self.extlm_type = self.extlm_packet_type_e.extlm_type_text # The kind of data is transported in EX sub packet
        self.extlm_entry_idx = 0 # The index used for a single data entry (1 to 4 bytes)
        self.extlm_entry_length = 0 # Number of bytes for a single data entry (1 to 4 bytes)
        self.exbus_payload = []  # Stores the payload for decoding after last byte ist rx'd.
        self.exbus_block_length = 0 # length of the block currently under decoding
        self.exbus_block_byte_idx = 0 # Index onto current data byte in block
        self.exbus_block_start = None  # Timestamp: Start of block
        self.exbus_block_end = None  # Timestamp: End of block
        self.exbus_payload_start = None  # Timestamp: Start of payload (w/o frame type)
        self.exbus_payload_end = None  # Timestamp: End of payload
        print("Initialized EXBUS HLA.")

        # Settings can be accessed using the same name used above.

        #print("Settings:", self.my_string_setting,
        #      self.my_number_setting, self.my_choices_setting)

    def decode(self, frame: AnalyzerFrame):
        '''
        Process a frame from the input analyzer, and optionally return a single `AnalyzerFrame` or a list of `AnalyzerFrame`s.

        The type and data values in `frame` will depend on the input analyzer.
        '''
        # New frame
        if self.exbus_frame_start == None and self.dec_fsm == self.dec_fsm_e.idle:
            self.exbus_frame_current_index = 0
            if frame.data['data'] == self.EXBUS_START_BYTE_MSTR_CH_DATA:
                print('Master: Start channel data frame detected.')
                self.exbus_frame_start = frame.start_time
                self.dec_fsm = self.dec_fsm_e.master_start_byte_rcvd
                self.exbus_frame_current_index += 1
                return AnalyzerFrame('Mstr:ChData', frame.start_time, frame.end_time, {})
            elif frame.data['data'] == self.EXBUS_START_BYTE_MSTR_TLM_REQ:
                print('Master: Start telemetry request frame.')
                self.exbus_frame_start = frame.start_time
                self.dec_fsm = self.dec_fsm_e.master_start_byte_rcvd
                self.exbus_frame_current_index += 1
                return AnalyzerFrame('Mstr:Tlm?', frame.start_time, frame.end_time, {})
            elif frame.data['data'] == self.EXBUS_START_BYTE_SLV_TLM_RSP:
                print('Slave: Telemetry reponse.')
                self.exbus_frame_start = frame.start_time
                self.dec_fsm = self.dec_fsm_e.slave_start_byte_rcvd
                self.exbus_frame_current_index += 1
                return AnalyzerFrame('Slv:Rsp', frame.start_time, frame.end_time, {})
            elif frame.data['data'] == self.EXBUS_START_BYTE_SLV_UNKNOWN1_RSP:
                print('Slave: Unknown response.')
                self.exbus_frame_start = frame.start_time
                self.dec_fsm = self.dec_fsm_e.slave_start_byte_rcvd
                self.exbus_frame_current_index += 1
                return AnalyzerFrame('Slv:UnknRsp', frame.start_time, frame.end_time, {})


        if self.dec_fsm == self.dec_fsm_e.master_start_byte_rcvd:
            if frame.data['data'] == self.EXBUS_REQ_RESP:
                print('Master: Slave should response.')
                self.dec_fsm = self.dec_fsm_e.packet_length_byte
                self.exbus_frame_current_index += 1
                return AnalyzerFrame('Mstr:ReqResp', frame.start_time, frame.end_time, {})
            elif frame.data['data'] == self.EXBUS_NO_RESP:
                print('Master: Slave, do not response!')
                self.dec_fsm = self.dec_fsm_e.packet_length_byte
                self.exbus_frame_current_index += 1
                return AnalyzerFrame('Mstr:NoResp', frame.start_time, frame.end_time, {})
        elif self.dec_fsm == self.dec_fsm_e.slave_start_byte_rcvd:
            if frame.data['data'] == self.EXBUS_RESP:
                print('Slave response.')
                self.dec_fsm = self.dec_fsm_e.packet_length_byte
                self.exbus_frame_current_index += 1
                return AnalyzerFrame('Slv:Resp', frame.start_time, frame.end_time, {})


        if self.dec_fsm == self.dec_fsm_e.packet_length_byte:
           print('Packet length byte read.')
           self.exbus_packet_length = int.from_bytes(frame.data['data'], byteorder='big')
           self.dec_fsm = self.dec_fsm_e.id_byte
           self.exbus_frame_current_index += 1
           return AnalyzerFrame('PkgLen', frame.start_time, frame.end_time, {})

        if self.dec_fsm == self.dec_fsm_e.id_byte:
           print('Packet ID byte read.')
           self.dec_fsm = self.dec_fsm_e.data_identifyer_byte
           self.exbus_frame_current_index += 1
           return AnalyzerFrame('PkgID', frame.start_time, frame.end_time, {})

        if self.dec_fsm == self.dec_fsm_e.data_identifyer_byte:
           self.dec_fsm = self.dec_fsm_e.data_block_len_byte
           self.exbus_frame_current_index += 1
           if frame.data['data'] == self.EXBUS_CHANNEL_VALUES: 
              print('Packet contains channel values.')
              self.packet_type = self.packet_type_e.channel_value_packet
              return AnalyzerFrame('Chan', frame.start_time, frame.end_time, {})
           elif frame.data['data'] == self.EXBUS_TELEMETRY: 
              print('Telemetry req or response.')
              self.packet_type = self.packet_type_e.telemetry_packet
              return AnalyzerFrame('Tlm', frame.start_time, frame.end_time, {})
           elif frame.data['data'] == self.EXBUS_TELEMETRY: 
              print('JetiBox key values or response string.')
              self.packet_type = self.packet_type_e.jetibox_packet
              return AnalyzerFrame('JetiBx', frame.start_time, frame.end_time, {})
           else:
              print('Unknown data block starts.')
              self.packet_type = self.packet_type_e.unknown_packet
              return AnalyzerFrame('unknown', frame.start_time, frame.end_time, {})
 

        if self.dec_fsm == self.dec_fsm_e.data_block_len_byte:
           print('Block length read.')
           self.exbus_frame_current_index += 1
           self.exbus_block_byte_idx = 0
           self.exbus_block_length = int.from_bytes(frame.data['data'], byteorder='big')
           # ExBus definition contains the flaw that the CRC postion cannot be detected
           # without length information which can only be verified by CRC. 
           if self.exbus_packet_length-2 == self.exbus_frame_current_index:
              self.dec_fsm = self.dec_fsm_e.packet_crc_lsb
           else:
              self.dec_fsm = self.dec_fsm_e.decoding_block
           return AnalyzerFrame('BlkLen', frame.start_time, frame.end_time, {})

        if self.dec_fsm == self.dec_fsm_e.decoding_block:
           self.exbus_frame_current_index += 1
           if self.exbus_block_byte_idx == 0:
              self.exbus_block_start = frame.start_time
           self.exbus_block_byte_idx += 1

           if self.packet_type == self.packet_type_e.channel_value_packet:
              if self.exbus_block_byte_idx < self.exbus_block_length:
                 # If we would like to decode all channel values this would be the
                 # place to do. Currently these values are simply ignored.
                 #print('Further channel data')
                 pass
              else: 
                 if self.exbus_frame_current_index == self.exbus_packet_length - 2:
                    self.dec_fsm = self.dec_fsm_e.packet_crc_lsb
                 else:
                    self.dec_fsm = self.dec_fsm_e.data_identifyer_byte
                 return AnalyzerFrame('ChnData', self.exbus_block_start, frame.end_time, {})
              
           elif self.packet_type == self.packet_type_e.telemetry_packet:
              # This is the region in which EX telemetry packets travel as sub-packets
              # in the ExBus packet 
              payload = int.from_bytes(frame.data['data'], byteorder='big')
              if self.exbus_block_byte_idx <= self.exbus_block_length:
                 print('Processing EX telemetry sub packet')
                 print(hex(payload))
                 #print(self.exbus_block_byte_idx, self.exbus_block_length)
                 if self.exbus_block_byte_idx == self.EXTLM_START_BYTE_POS and payload&0x0F == self.EXTLM_START_BYTE:
                    return AnalyzerFrame('ExTlmStart', frame.start_time, frame.end_time, {})
                 elif self.exbus_block_byte_idx == self.EXTLM_PKG_TYPE_AND_LENGTH_POS:
                    self.extlm_packet_length = payload&0b00111111
                    print(self.extlm_packet_length)
                    if payload>>6 == self.EXTLM_PKG_TYPE_TEXT:
                       print('EX text telemetry packet encountered')
                       self.extlm_type = self.extlm_packet_type_e.extlm_type_text
                       self.tag_str = ('{}').format(self.extlm_packet_length)
                       return AnalyzerFrame('Txt', frame.start_time, frame.end_time, {'Len': self.tag_str})
                    if payload>>6 == self.EXTLM_PKG_TYPE_DATA:
                       print('EX data telemetry packet encountered')
                       self.extlm_type = self.extlm_packet_type_e.extlm_type_data
                       self.tag_str = ('{}').format(self.extlm_packet_length)
                       return AnalyzerFrame('Data', frame.start_time, frame.end_time, {'Len': self.tag_str})
                    if payload>>6 == self.EXTLM_PKG_TYPE_MESSAGE:
                       print('EX message telemetry packet encountered')
                       self.extlm_type = self.extlm_packet_type_e.extlm_type_message
                       self.tag_str = ('{}').format(self.extlm_packet_length)
                       return AnalyzerFrame('Msg', frame.start_time, frame.end_time, {'Len': self.tag_str})
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
                          if payload&0b00001111 == self.EXTLM_DATA_TYPE_6b:
                             self.extlm_entry_length = self.EXTLM_DATA_TYPE_6b_LEN
                          elif payload&0b00001111 == self.EXTLM_DATA_TYPE_14b:
                             self.extlm_entry_length = self.EXTLM_DATA_TYPE_14b_LEN
                          elif payload&0b00001111 == self.EXTLM_DATA_TYPE_22b:
                             self.extlm_entry_length = self.EXTLM_DATA_TYPE_22b_LEN
                          print('First data entry encountered')
                          self.tag_str = ('ID:{}, type:{}, len:{}').format(hex(payload>>4),payload&0b00001111, self.extlm_entry_length)
                          print (self.tag_str)
                       if self.extlm_entry_idx == self.extlm_entry_length:
                          # Last byte of data entry
                          self.extlm_entry_idx = 0
                          return AnalyzerFrame('Data', self.exbus_block_start, frame.end_time, {'Data': self.tag_str})
                       else:
                          # one of the middle bytes of data entry
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
           print('Packet CRC LSB.')
           self.exbus_block_start = frame.start_time
           self.dec_fsm = self.dec_fsm_e.packet_crc_msb
           self.exbus_frame_current_index += 1
           return None

        if self.dec_fsm == self.dec_fsm_e.packet_crc_msb:
           self.exbus_frame_current_index += 1
           print('Packet CRC MSB.')
           #print(self.exbus_packet_length, self.exbus_frame_current_index)
           self.dec_fsm = self.dec_fsm_e.idle
           self.exbus_frame_start = None
           #print(self.exbus_frame_current_index, self.exbus_packet_length)
           if self.exbus_frame_current_index == self.exbus_packet_length:
              return AnalyzerFrame('PkgCrc', self.exbus_block_start, frame.end_time, {})
           else:
              return AnalyzerFrame('PkgLenErr!', frame.start_time, frame.end_time, {})               
















        # Analog payload
        if self.dec_fsm == self.dec_fsm_e.analog_payload:
            payload = int.from_bytes(frame.data['data'], byteorder='big')
            if self.exbus_frame_current_index == 1:  # First payload byte
                self.exbus_payload_start = frame.start_time
                self.exbus_payload.append(payload)
                self.exbus_frame_current_index += 1
                #print('Payload start ({}): {:2x}'.format(self.exbus_frame_current_index, payload))
            elif self.exbus_frame_current_index < 22:  # ... still collecting payload bytes ...
                self.exbus_payload.append(payload)
                self.exbus_frame_current_index += 1
                #print('Adding payload ({}): {:2x}'.format(self.exbus_frame_current_index, payload))
            elif self.exbus_frame_current_index == 22:  # Last analog payload byte received
                analyzerframe = None
                self.dec_fsm = self.dec_fsm_e.digital_payload
                self.exbus_payload_end = frame.end_time
                self.exbus_payload.append(payload)
                #print('Payload complete ({}): {:2x}'.format(self.exbus_frame_current_index, payload))
                #print(self.exbus_payload)
                # RC channels packed
                # 11 bits per channel, 16 channels, 176 bits (22 bytes) total
                bin_str = ''
                channels = []
                for i in self.exbus_payload:
                    bin_str += format(i, '08b')[::-1]  # Format as bits and reverse order
                print(bin_str)
                for i in range(16):
                    value = int(bin_str[0 + 11 * i : 11 + 11 * i][::-1], 2)  # 'RC' value
                    value_ms = int((value * 1024 / 1639) + 881)  # Converted to milliseconds
                    channels.append(value)
                    channels.append(value_ms)
                print(channels)
                payload_str = ('Ch1:{} ({}µs), Ch2:{} ({}µs), Ch3:{} ({}µs), Ch4:{} ({}µs), ' + \
                               'Ch5:{} ({}µs), Ch6:{} ({}µs), Ch7:{} ({}µs), Ch8:{} ({}µs), ' + \
                               'Ch9:{} ({}µs), Ch10:{} ({}µs), Ch11:{} ({}µs), Ch12:{} ({}µs), ' + \
                               'Ch13:{} ({}µs), Ch14:{} ({}µs), Ch15:{} ({}µs), Ch16:{} ({}µs)').format(*channels)
                print(payload_str)
                analyzerframe = AnalyzerFrame('exbus_analog_payload', self.exbus_payload_start, frame.end_time, {
                        'payload': payload_str})
                return analyzerframe

        # Digital payload
        if self.dec_fsm == self.dec_fsm_e.digital_payload:
            self.dec_fsm = self.dec_fsm_e.stop_sync_byte
            payload = int.from_bytes(frame.data['data'], byteorder='big')
            print(payload)
            if payload == 0:
                return AnalyzerFrame('', frame.start_time, frame.end_time, {})
            else:
                payload_str = ''
                sep = False
                if (payload & 0x8) != 0:
                    payload_str += "Failsafe"
                    sep = True
                if (payload & 0x4) != 0:
                    if sep:
                        payload_str += ", "
                    payload_str += "Frame lost"
                    sep = True
                if (payload & 0x2) != 0:
                    if sep:
                        payload_str += ", "
                    payload_str += "Ch18 on"
                    sep = True
                if (payload & 0x1) != 0:
                    if sep:
                        payload_str += ", "
                    payload_str += "Ch17 on"
                print(payload_str)
                return AnalyzerFrame('exbus_digital_payload', frame.start_time, frame.end_time, {'payload': payload_str})

