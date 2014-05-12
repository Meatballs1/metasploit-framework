##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

##
# This module is based on, inspired by, or is a port of a plugin available in the Onapsis Bizploit Opensource ERP Penetration Testing framework - http://www.onapsis.com/research-free-solutions.php.
# Mariano Nunez (the author of the Bizploit framework) helped me in my efforts in producing the Metasploit modules and was happy to share his knowledge and experience - a very cool guy.
# Id also like to thank Chris John Riley, Ian de Villiers and Joris van de Vis who have Beta tested the modules and provided excellent feedback. Some people just seem to enjoy hacking SAP :)
##

require 'msf/core'
require 'msf/core/exploit/sap'

class Metasploit4 < Msf::Auxiliary

  include Msf::Exploit::SAP
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize
    super(
        'Name'        => 'SAP RFC Client Enumerator',
        'Description' => %q{
                       This module attempts to brute force the available SAP clients via the RFC interface.
                       Default clients can be tested without needing to set a CLIENT.
                       This module can execute through a SAP Router if SRHOST and SRPORT values are set.
                       The module requires the NW RFC SDK from SAP as well as the Ruby wrapper nwrfc (http://rubygems.org/gems/nwrfc).
                    },
        'References'  => [[ 'URL', 'http://labs.mwrinfosecurity.com' ]],
        'Author'      => [ 'nmonkee' ],
        'License'     => BSD_LICENSE
    )

        register_options(
          [
            Opt::RPORT(3342),
          ], self.class)
  end

  def run_host(rhost)
    user = "SAP*"
    password = Rex::Text.rand_text_alpha(8)
    rport = datastore['RPORT']

    saptbl = Msf::Ui::Console::Table.new(
              Msf::Ui::Console::Table::Style::Default,
              'Header'  => "[SAP] Clients #{rhost}:#{rport}",
              'Columns' =>
                [
                  "host",
                  "port",
                  "client",
                ])

    client_list.each do |client|
      vprint_status("#{rhost}:#{rport} [SAP] trying client: #{client}")
      begin
        conn = login(rhost, rport, client, user, password)
        print_good("#{rhost}:#{rport} [SAP] client found: #{client}")
        saptbl << [rhost, rport, client]
        report_auth_info(
          :host          => rhost,
          :sname         => 'sap-gateway',
          :proto         => 'tcp',
          :port          => rport,
          :client        => client,
          :user          => user,
          :pass          => password,
          :sysnr         => system_number(rport),
          :source_type   => 'user_supplied',
          :target_host   => rhost,
          :target_port   => rport
        )

      rescue NWError => e
        case e.message.to_s
        when /not available in this system/i
          vprint_error("#{rhost}:#{rport} [SAP] client #{client} does not exist")
        when /Logon not possible/i
          vprint_error("#{rhost}:#{rport} [SAP] client #{client} does not exist")
        when /Gateway not connected to local/i
          vprint_error("#{rhost}:#{rport} [SAP] Gateway not configured")
          break
        when /Connection refused/i
          vprint_error("#{rhost}:#{rport} [SAP] client #{client} connection refused")
          break
        end
      ensure
        if conn
          conn.disconnect
        end
      end
    end

    if saptbl.rows.count > 0
      print(saptbl.to_s)
    end
  end
end

