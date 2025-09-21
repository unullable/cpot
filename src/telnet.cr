require "socket"
require "./tcp"
require "./logger"
require "./honeypot"
require "./telegram"

class TelnetException < Exception
end

class Honeypot::Telnet
  include Honeypot
  getter port : Int32
  
  def initialize(@port)
    @maxtries = 100
    @filter = ["SSH", "ssh", "GET", "POST", "HEAD", "Docker", "Host", "User", "Accept"] # non telnet traffic
    @notifier = Telegram.new
    @reporter = AbuseIPDB.new
    @server = TCPServer.new "::", @port
    @last_reported_ip = ""
  end
  
  private def report(ip, msg)
    if ip != @last_reported_ip
      @reporter.report(ip, msg)
      @last_reported_ip = ip
    end
  end

  private def send_banner(conn)
    conn << "+-------------------------------------+\r\n"
    conn << "|    Welcome To CPoT IoT Honeypot.    |\r\n"
    conn << "+-------------------------------------+\r\n"
  end

  private def send_username_prompt(conn)
    conn << "(dvr) login: "
  end

  private def send_password_prompt(conn)
    conn << "Password: "
  end
  
  private def receive_data(conn, timeout) : String | Nil
    conn.read_timeout=timeout.seconds
    buf = conn.gets

    if buf
      return if buf.size > 30
      return unless buf[0].printable?
      @filter.each { |f| return nil if buf.includes?(f) }
    end
    buf
  end

  private def send_failed_prompt(conn)
    conn << "Wrong Password"
    conn << '\n'
  end

  private def log(host : String, username : String, password : String)
    LogToFile::TELNET_LOGGER.warn {"login from #{format_ip(host)} with #{username}:#{password}"}
  end

  private def log(host, payload)
    LogToFile::TELNET_LOGGER.info {["host", format_ip(host), "payload", payload]}
  end
  
  private def fake_login_system(s)
    combos = Hash(String, String).new
    tries = 0
    send_banner(s)
    while (true)
      begin
        send_username_prompt(s)
        username = receive_data(s, 5)
        send_password_prompt(s)
        password = receive_data(s, 5)
    
        print_success "[Telnet] #{format_ip(s.remote_address.address)} -> #{username}:#{password}" 
        log(s.remote_address.address.to_s, username, password) if !username.nil? && !password.nil?
        if username.nil?
            combos[password] = "" if password 
        else
            combos[password] = username if password
        end
        tries += 1
        raise TelnetException.new("MAX ATTEMPTS EXCEEDED") if tries >= @maxtries
      rescue 
        break
      end
    end
    ip = format_ip(s.remote_address.address)
    @notifier.send_notification("TELNET ATTACK - #{ip}\nCredentials Tried:\n#{combos.to_s}\nAttacker Info \n#{ip_info(s.remote_address.address)}") unless combos.empty?

    {% if flag?(:report_abuse) %}
      report(ip, "telnet scanner/bruter (port:#{@port})")
    {% end %}
    s.close
  end

  def worker  
    print_info "[telnet] listening on #{@port}"
    loop do 
      client = begin
        @server.accept?
      rescue ex
        print_err "[telnet|#{port}] Exception: #{ex.message}"
        break
      end
      if client
        spawn fake_login_system(client)
      end
    end
  end
end
