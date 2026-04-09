# Rate limiting using the token bucket algorithm

require "time"
require "./honeypot"

class Honeypot::TokenBucket
  property rate     : Int32
  property capacity : Int32
  property tokens   : Int32

  def initialize(@rate, @capacity)
    @tokens = capacity
    @last_refill = Time.utc.to_unix
  end

  private def min(a, b)
    if a < b
      a
    else
      b
    end
  end

  def allow_request : Bool
    now = Time.utc.to_unix
    @tokens += (now - @last_refill) * rate
    @tokens = min(@tokens, capacity)
    @last_refill = now
    if @tokens >= 1
      @tokens -= 1
      return true
    else
      return false
    end
  end
end
