module RubySMB
  module Fscc
    module FileInformation
      # The FileNamesInformation Class as defined in
      # [2.4.26 FileNamesInformation](https://msdn.microsoft.com/en-us/library/cc232077.aspx)
      class FileNamesInformation < BinData::Record
        # The value set in the InformationLevel field of an SMB1 request to indicate
        # the response should use this Information Class Structure.
        SMB1_FLAG = 0x0103
        # The value set in the InformationLevel field of an SMB2 request to indicate
        # the response should use this Information Class Structure.
        SMB2_FLAG = 0x0C

        endian :little

        uint32           :next_offset,      label: 'Next Entry Offset'
        uint32           :file_index,       label: 'File Index'
        uint32           :file_name_length, label: 'File Name Length',  initial_value: -> { file_name.do_num_bytes }
        string16         :file_name,        label: 'File Name',         read_length: -> { file_name_length }
      end
    end
  end
end
