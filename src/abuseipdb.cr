require "http/client"
require "uri"
require "dotenv"

class Honeypot::AbuseIPDB
  include Honeypot

  getter reported : Int32

  def initialize
    @reported = 0
    @base = "https://api.abuseipdb.com/api/v2/report"
  end

  # Load API key from .env
  def api_key
    env = Dotenv.load
    env["ABUSEIPDB_API_KEY"]
  end
  
  # Create a report for *ip* with abuse reason *comment*
  def report(ip : String, comment : String, categories : Array(Category))
    headers = HTTP::Headers.new
    headers["Key"] = api_key
    headers["Accept"] = "application/json"
    headers["Content-Type"] = "application/x-www-form-urlencoded"

    categories_str = String.new
    categories.each_with_index do |cat, i|
      categories_str += cat.value.to_s
      categories_str += ',' if i < categories.size-1
    end

    data = URI::Params.encode({
      "ip" => ip,
      "categories" => categories_str,
      "comment" => comment
    })

    @reported = if @reported == Int32::MAX
                  0
                else
                  @reported + 1
                end

    response = HTTP::Client.post(@base, headers: headers, body: data)
    response.status_code
  end
end

enum Honeypot::AbuseIPDB::Category
  FTP_BRUTE_FORCE = 5
  OPEN_PROXY = 9
  PORT_SCAN = 14
  HACKING = 15
  SQL_INJECTION = 16
  BRUTE_FORCE = 18
  EXPLOITED_HOST = 20
  SSH = 22
  IOT_TARGETED = 23
end

