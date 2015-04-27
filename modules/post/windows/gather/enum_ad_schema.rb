##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex'
require 'msf/core'

class Metasploit3 < Msf::Post
  include Msf::Auxiliary::Report
  include Msf::Post::Windows::LDAP

  def initialize(info = {})
    super(update_info(
      info,
      'Name'         => 'Windows Gather Active Directory Schema',
      'Description'  => %{
        This module will retrieve the Active Directory LDAP schema and list values which have been modified
        since the root domain was created.
      },
      'License'      => MSF_LICENSE,
      'Author'       => [
        'Ben Campbell',
      ],
      'Platform'     => [ 'win' ],
      'SessionTypes' => [ 'meterpreter' ]
    ))

    register_options([
      OptBool.new('STORE_LOOT', [true, 'Store file in loot.', false]),
    ], self.class)
  end

  def ad2dt(ad_date)
    DateTime.strptime(ad_date,'%Y-%m-%d %H:%M:%S.%L')
  end

  def dt2ad(date)
    date.strftime('%Y%m%d%H%M%S.%1NZ')
  end

  def find_root_creation_date(results)
    creation_date = nil
    results.each do |result|
      # TODO: check better
      field = result[1][:value]
        if field.nil?
          next
        else
          dt_value = ad2dt(field)
          if creation_date.nil?
            creation_date = dt_value
          else
            creation_date = dt_value if creation_date < dt_value
          end

        end
      end

    creation_date
  end

  def run
    max_search = 0

    # Find creation date
    creation_query = '(&(objectClass=crossRef)(systemFlags=3))'
    creation_fields = ['dnsRoot', 'whenCreated']
    creation_dn = 'CN=Partitions,CN=Configuration,DC=test,DC=lab'

    begin
      q = query(creation_query, max_search, creation_fields, creation_dn)
    rescue ::RuntimeError, ::Rex::Post::Meterpreter::RequestError => e
      # Can't bind or in a network w/ limited accounts
      print_error(e.message)
      return
    end

    if q.nil? || q[:results].empty?
      print_status('No results returned.')
    else
      creation_date = find_root_creation_date(q[:results])
    end

    vprint_status("Root domain creation date: #{creation_date}")
    query_filter = "(&(|(objectClass=classSchema)(objectClass=attributeSchema))(whenChanged>=#{dt2ad(creation_date)}))"
    fields = ['cn', 'objectClass', 'attributeSyntax', 'whenChanged','whenCreated', 'searchFlags']
    dn = 'CN=Schema,CN=Configuration,DC=test,DC=lab'

    begin
      q = query(query_filter, max_search, fields, dn)
    rescue ::RuntimeError, ::Rex::Post::Meterpreter::RequestError => e
      # Can't bind or in a network w/ limited accounts
      print_error(e.message)
      return
    end

    if q.nil? || q[:results].empty?
      print_status('No results returned.')
    else
      results_table = parse_results(q[:results], fields)
      print_line results_table.to_s
    end
  end

  # Takes the results of LDAP query, parses them into a table
  # and records and usernames as {Metasploit::Credential::Core}s in
  # the database.
  #
  # @param [Array<Array<Hash>>] the LDAP query results to parse
  # @return [Rex::Ui::Text::Table] the table containing all the result data
  def parse_results(results, fields)
    results_table = Rex::Ui::Text::Table.new(
      'Header'     => "Domain Schema",
      'Indent'     => 1,
      'SortIndex'  => -1,
      'Columns'    => fields
    )

    results.each do |result|
      row = []

      result.each do |field|
        if field.nil?
          row << ""
        else
          row << field[:value]
        end
      end

      results_table << row
    end
    results_table
  end
end
