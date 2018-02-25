module RubySMB
  module SMB1
    module Packet
      # Namespace for the Transaction sub-protocol documented in
      # [2.2.4.33 SMB_COM_TRANSACTION (0x25)](https://msdn.microsoft.com/en-us/library/ee441489.aspx)
      module Trans
        require 'ruby_smb/smb1/packet/trans/subcommands'
        require 'ruby_smb/smb1/packet/trans/data_block'
        require 'ruby_smb/smb1/packet/trans/request'
        require 'ruby_smb/smb1/packet/trans/response'
        require 'ruby_smb/smb1/packet/trans/peek_named_pipe_request'
        require 'ruby_smb/smb1/packet/trans/peek_named_pipe_response'
      end
    end
  end
end
