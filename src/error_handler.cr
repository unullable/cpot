require "http/server/handler"

class HTTP::ErrorHandler
  include HTTP::Handler

  def initialize(@verbose : Bool = false, @log = Log.for("http.server"))
  end

  def call(context : HTTP::Server::Context) : Nil
    call_next(context)
  rescue ex : HTTP::Server::ClientError
    @log.debug(exception: ex.cause) { ex.message }
  rescue ex : Exception
    @log.error(exception: ex) { "Unhandled exception" }
    unless context.response.closed? || context.response.wrote_headers?
      if @verbose
        context.response.reset
        context.response.status = HTTP::Status::FORBIDDEN
        context.response.content_type = "text/plain"
        context.response.print("ERROR: ")
        context.response.puts(ex.inspect_with_backtrace)
      else
        context.response.respond_with_status(HTTP::Status::FORBIDDEN)
      end
    end
  end
end
