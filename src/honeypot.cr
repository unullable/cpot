require "colorize"
require "http/client"
require "json"

module Honeypot
  def print_err(msg)
    puts msg.colorize(:red)
  end
  def print_info(msg)
    puts msg.colorize(:yellow)
  end
  def print_success(msg)
    puts msg.colorize(:green)
  end
  def format_ip(c)
    c.remote_address.address[7..]
  end
  def format_ip(address : String)
    addr = address
    begin
        address[7..]
    rescue
        address
    end
  end
  
  def ip_info(ip : String) : String
    res : String = ""
    response = HTTP::Client.get "http://ip-api.com/json/#{ip}"
    if response.status_code == 200
        info = JSON.parse(response.body)
        return "" if info["status"] == "fail"
        res += "\tCC:\t" + info["countryCode"].to_s + '\n'
        res += "\tCountry:\t" + info["country"].to_s + '\n'
        res += "\tISP: " + info["isp"].to_s
    end
    res
  end
end