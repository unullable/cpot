require "http/client"
require "digest/sha256"
require "colorize"
require "json"

class Honeypot::Telegram
  include Honeypot
  property bot_token  : String   = ""
  property chat_id    : String   = ""
  property message    : String   = ""

  def initialize
    load_config
    @url = "https://api.telegram.org/bot#{bot_token}"
    @executed = Set(String).new
  end

  def safe_ip(ip : String) : String
    ip.gsub('.', "[.]")
  end

  def abuselink(ip : String) : String
    "https://www.abuseipdb.com/check/#{ip}"
  end

  def send_notification(report : String)
    data = {
      "chat_id" => @chat_id,
      "text"    => "⚠️ #{report}"
    }.to_json
    resp = HTTP::Client.post(
        @url + "/sendMessage",
        headers:HTTP::Headers{"Content-Type" => "application/json"},
        body: data
    )
  end

  def load_config
    begin
      json = JSON.parse(File.read("./config.json"))
    rescue e 
      puts "Exception: #{e.message}"
      exit
    end
    @bot_token = json["bot_token"].to_s
    @chat_id = json["chat_id"].to_s
  end
end
