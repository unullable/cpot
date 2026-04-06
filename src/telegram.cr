require "http/client"
require "digest/sha256"
require "colorize"
require "json"
require "dotenv"

class Honeypot::Telegram
  include Honeypot
  property bot_token  : String   = ""
  property chat_id    : String   = ""
  property message    : String   = ""

  # Create a new telegram notifier
  def initialize
    @url = "https://api.telegram.org/bot"
    @executed = Set(String).new
  end

  # :nodoc:
  def safe_ip(ip : String) : String
    ip.gsub('.', "[.]")
  end

  # Get AbuseIPDB for *ip* formatted as HTML
  def abuselink(ip : String) : String
    "<a href=\"https://www.abuseipdb.com/check/#{ip}\">AbuseIPDB</a>"
  end

  # Notify admin for *report*
  def send_notification(report : String)
    if chat_id.empty?
      print_info "Warning: Chat ID is empty, call load_tokens!"
      return
    end

    data = {
      "chat_id" => @chat_id,
      "text"    => "⚠️ #{report}",
      "parse_mode" => "HTML"
    }.to_json

    if bot_token.empty?
      print_info "Warning: Bot token is empty, call load_tokens!"
      return
    end

    api_url = "#{@url}#{bot_token}/sendMessage"

    resp = HTTP::Client.post(
        api_url,
        headers:HTTP::Headers{"Content-Type" => "application/json"},
        body: data
    )
  end

  # Load bot token and chat id
  def load_tokens
    env = Dotenv.load
    @bot_token = env["TELEGRAM_BOT_TOKEN"]
    @chat_id   = env["TELEGRAM_CHAT_ID"]
  end
end
