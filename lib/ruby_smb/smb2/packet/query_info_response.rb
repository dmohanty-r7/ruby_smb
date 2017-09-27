module RubySMB
  module SMB2
    module Packet
      # An SMB2 Query Response Packet as defined in
      # [2.2.38 SMB2 QUERY_INFO Response](https://msdn.microsoft.com/en-us/library/cc246559.aspx)
      class QueryInfoResponse < RubySMB::GenericPacket
        endian :little

        smb2_header   :smb2_header
        uint16        :structure_size,       label: 'Structure Size',       initial_value: 9
        uint8         :output_buffer_offset, label: 'Output Buffer Offset', initial_value: -> { buffer.abs_offset }
        uint32        :output_buffer_length, label: 'Output Buffer Length'
        string        :buffer,               label: 'Buffer', length: -> { data_length }

        def initialize_instance
          super
          smb2_header.command     = RubySMB::SMB2::Commands::QUERY_INFO
          smb2_header.flags.reply = 1
        end
      end
    end
  end
end
