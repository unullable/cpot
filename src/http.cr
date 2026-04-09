require "http/server"
require "socket"
require "json"

require "./error_handler"
require "./client_handler"

class Honeypot::Http
  include Honeypot

  getter port : UInt16

  # Create a new HTTP Honeypot on *port*
  def initialize(@port)
    @server = HTTP::Server.new([
      HTTP::ErrorHandler.new,
      HTTP::ClientHandler.new(port),
    ])
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
