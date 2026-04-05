require "http/client"
require "xml"
require "uri"
require "./honeypot"

class Honeypot::DorkerGenerator
  include Honeypot

  getter engines : Array(String)

  def initialize
    @engines = [
      "google",
      "bing",
      "kagi",
      "duckduckgo"
    ]
  end

  # Add a new engine
  #
  # NOTE: This could be a search aggregator like degoog too
  def add(new_engine : String)
    @engines << new_engine
  end

  # Get a list of dork urls for *dork*
  def get(dork : String) : Array(String)
    print_info "Warning: Empty dork" if dork.empty?
    dork_encoded = URI.encode_path_segment(dork)
    dork_results = [] of String
    @engines.each do |engine|
      dork_results << "<a href=\"https://#{engine}.com/search?q=#{dork_encoded}\">#{engine}</a>"
    end
    dork_results
  end
end
