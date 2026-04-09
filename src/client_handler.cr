require "http/server/handler"
require "json"
require "./tcp"
require "./logger"
require "./honeypot"
require "./telegram"
require "./abuseipdb"
require "./detection"
require "./dork_generator"
require "./circular_array"
require "./token_bucket.cr"

class RateLimitReachedException < Exception
end

class HTTP::ClientHandler
  include HTTP::Handler
  include Honeypot

  def initialize(@port : UInt16)
    @generator = DorkerGenerator.new
    @cache = CircularArray(String).new(100)
    @token_bucket = TokenBucket.new(1, 50)
    @notifier = Telegram.new
    @reporter = AbuseIPDB.new

    {% if flag?(:report_telegram) %}
      @notifier.load_tokens
    {% end %}
  end
  
  private def is_proxy_scanner(request : HTTP::Request) : Bool
    return false if request.nil?
    return true if request.method == "CONNECT"
    false
  end
  
  private def is_malicious(request : HTTP::Request) : String
    detection = Detection.new(request)
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
    }.to_pretty_json
    end
  end

  def call(context : HTTP::Server::Context) : Nil
    unless context.response.closed? || context.response.wrote_headers?
      # apply rate limiting
      raise RateLimitReachedException.new("RATE LIMIT REACHED") unless @token_bucket.allow_request

      context.response.content_type = "text/html"
      context.response.print "<title>CPoT</title>"
      context.response.print "<h1><b>Welcome to <a href=https://github.com/unullable/cpot>CPoT</a></b></h1>"
      context.response.print "<p>A Low Interaction Honeypot In CRYSTAL.</p>"
      
      bodyStr = context.request.body.try &.gets_to_end
      log_to_file context.request, @port, bodyStr
      context.request.body = bodyStr
      addr = context.request.remote_address

      if addr.is_a?(Socket::IPAddress)
          addr = addr.address
          ip = format_ip(addr.to_s)

          # check if its an http proxy scanner
          if is_proxy_scanner(context.request)
            {% if flag?(:report_telegram) %}
              @notifier.send_notification("\
                <b>Honeypot Alert: Detected proxy scanner #{@notifier.safe_ip(ip)} on port #{@port}</b> /n \
                🌍 Attacker Info:\n#{ip_info(ip)}"
              )
            {% end %}

            {% if flag?(:report_abuse) %}
              if @cache.find(ip).nil?
                @reporter.report(ip, "Open Proxy Scanner (port:#{@port})", [AbuseIPDB::Category::OPEN_PROXY])
                @cache.add(ip)
              end
            {% end %}
          end

          msg = is_malicious(context.request)
          tmsg = msg
          unless msg.empty?
            {% if flag?(:report_telegram) %}
              # Add dorks ONLY on notifications
              if msg.includes?("Accessed")
                tmsg += '\n'
                @generator.get(context.request.path + " exploit").each do |dork|
                  tmsg += "InfoDork: " + dork + '\n'
                end
              end

              @notifier.send_notification("\
                <b>Honeypot Alert: Detected BoT #{@notifier.safe_ip(ip)}</b>.\n \
                To see abuse info/reports go to: #{@notifier.abuselink(ip)} \n\n \
                🌍 Attacker Info:\n#{ip_info(ip)} \n \
                👨🏻‍💻 Details:\n #{tmsg}"
              )
            {% end %}

            {% if flag?(:report_abuse) %}
              if @cache.find(ip).nil?
                @reporter.report(ip, "CPoT triggered at tcp/#{@port}.\
                #{msg}", [AbuseIPDB::Category::HACKING])
                @cache.add(ip)
              end
            {% end %}
          end
      end
    end
  end
end