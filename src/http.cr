require "http/server"
require "socket"
require "json"
require "./tcp"
require "./logger"
require "./honeypot"
require "./telegram"
require "./abuseipdb"
require "./detection"
require "./dork_generator"
require "./circular_array"

class Honeypot::Http
  include Honeypot

  getter port : Int32

  # Create a new HTTP Honeypot on *port*
  def initialize(@port)
    @notifier = Telegram.new
    @reporter = AbuseIPDB.new
    @generator = DorkerGenerator.new
    @seen = CircularArray(String).new

    {% if flag?(:report_telegram) %}
      @notifier.load_tokens
    {% end %}

    @server = HTTP::Server.new do |ctx| 
      ctx.response.content_type = "text/html"
      ctx.response.print "<title>CPoT</title>"
      ctx.response.print "<h1><b>Welcome to <a href=https://github.com/unullable/cpot>CPoT</a></b></h1>"
      ctx.response.print "<p>A Low Interaction Honeypot In CRYSTAL.</p>"

      bodyStr = ctx.request.body.try &.gets_to_end
      log_to_file ctx.request, port, bodyStr
      ctx.request.body = bodyStr
      addr = ctx.request.remote_address

      if addr.is_a?(Socket::IPAddress)
          addr = addr.address
          ip = format_ip(addr.to_s)

          # check if its an http proxy scanner
          if is_proxy_scanner(ctx.request)
            {% if flag?(:report_telegram) %}
              if @seen.find(ip).nil?
                @notifier.send_notification("\
                  <b>Honeypot Alert: Detected proxy scanner #{@notifier.safe_ip(ip)} on port #{@port}</b> /n \
                  🌍 Attacker Info:\n#{ip_info(ip)}"
                )
                @seen.add(ip)
              end
            {% end %}

            {% if flag?(:report_abuse) %}
              if @seen.find(ip).nil?
                @reporter.report(ip, "Open Proxy Scanner (port:#{@port})", [AbuseIPDB::Category::OPEN_PROXY])
                @seen.add(ip)
              end
            {% end %}
            next
          end
          
          msg = is_malicious(ctx.request)
          unless msg.empty?
            if msg.includes?("Accessed")
              msg += '\n'
              @generator.get(ctx.request.path + " exploit").each do |dork|
                  msg += "InfoDork: " + dork + '\n'
              end
            end

            {% if flag?(:report_telegram) %}
              if @seen.find(ip).nil?
                @notifier.send_notification("\
                  <b>Honeypot Alert: Detected BoT #{@notifier.safe_ip(ip)}</b>.\n \
                  To see abuse info/reports go to: #{@notifier.abuselink(ip)} \n\n \
                  🌍 Attacker Info:\n#{ip_info(addr.to_s)} \n \
                  👨🏻‍💻 Details:\n #{msg}"
                )
                @seen.add(ip)
              end
            {% end %}

            {% if flag?(:report_abuse) %}
              @reporter.report(ip, "CPoT triggered at tcp/#{@port}.\nDetails:\n#{msg}", [AbuseIPDB::Category::HACKING])
            {% end %}
          end
      end
    end
  end
  
  private def is_proxy_scanner(req : HTTP::Request) : Bool
    return false if req.nil?
    return true if req.method == "CONNECT"
    false
  end
  
  private def is_malicious(req : HTTP::Request) : String
    detection = Detection.new(req)
    detection.judge
  end

  private def log_to_file(req, port, body)
    remote_ip = req.remote_address.not_nil!
    ip = format_ip(remote_ip.address.to_s) if remote_ip.is_a?(Socket::IPAddress)

    print_info "[http] method: #{ip}:#{req.method}:#{req.path}"

    LogToFile::HTTP_LOGGER.info do
    {
      type: "http",
      port: port,
      ip: ip,
      method: req.method,
      endpoint: req.path,
      headers: req.headers.to_h,
      body: body || "None"
    }.to_pretty_json()
    end
  end

  # :nodoc:
  def worker
    begin
      address = @server.bind_tcp "::", @port
      print_info "[http] listening on http://#{address}"
      @server.listen
    rescue e
      print_err "[http] exception: #{e}"
      exit 1
    end
  end
end
