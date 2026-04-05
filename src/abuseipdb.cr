require "http/client"
require "uri"
require "dotenv"

class Honeypot::AbuseIPDB
  property reported : Int32

  def initialize
    @reported = 0
    @base = "https://api.abuseipdb.com/api/v2/report"
  end

  # Load API key from .env
  def api_key
    ht = Dotenv.load
    ht["ABUSEIPDB_API_KEY"]
  end
  
  # Create a report for *ip* with abuse reason *comment*
  def report(ip : String, comment : String)
    headers = HTTP::Headers.new
    headers["Key"] = api_key
    headers["Accept"] = "application/json"
    headers["Content-Type"] = "application/x-www-form-urlencoded"

    data = URI::Params.encode({
      "ip" => ip,
      "categories" => "15,19",
      "comment" => comment
    })

    @reported += 1
    response = HTTP::Client.post(@base, headers: headers, body: data)
    response.status_code
  end
end
