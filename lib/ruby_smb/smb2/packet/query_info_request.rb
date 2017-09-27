module RubySMB
  module SMB2
    module Packet
      # An SMB2 Query Info Request Packet as defined in
      # [2.2.37 SMB2 QUERY_INFO Request](https://msdn.microsoft.com/en-us/library/cc246557.aspx)
      class QueryInfoRequest < RubySMB::GenericPacket
        endian :little

        smb2_header           :smb2_header
        uint16                :structure_size,         label: 'Structure Size',         initial_value: 41
        uint8                 :info_type,              label: 'Info Type'
        uint8                 :file_info_class,        label: 'File Info Class'
        uint32                :buffer_length,          label: 'Buffer Length'
        uint16                :buffer_offset,          label: 'Buffer Offset',          initial_value: 96
        uint16                :reserved,               label: 'Reserved',               initial_value: 0
        uint32                :additional_information, label: 'Additional Information', initial_value: 0
        smb2_fileid           :file_id,                label: 'File ID'
        string                :buffer,                 label: 'Buffer'

        def initialize_instance
          super
          smb2_header.command = RubySMB::SMB2::Commands::QUERY_INFO
        end
      end
    end
  end
end
