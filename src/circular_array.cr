require "./honeypot"

# A stack allocated circular array
#
# NOTE: Prevent reporting the same host multiple times in a row.
class Honeypot::CircularArray(T)
  include Honeypot

  # Creates a new CircularArray with size *CIRCULAR_ARRAY_SIZE*
  def initialize
    @table = Array(T?).new(CIRCULAR_ARRAY_SIZE, nil)
    @index = 0
  end

  # Add an element to the table.
  #
  # NOTE: Cost: O(1)
  def add(val : T)
    print_info "Adding value: #{val}"
    @table[@index] = val
    @index = (@index + 1) % CIRCULAR_ARRAY_SIZE
  end

  # Find an element in table.
  #
  # NOTE: Cost: O(CIRCULAR_ARRAY_SIZE)
  def find(val : T) : T?
    @table.each do |e|
      unless e.nil?
        return e if e == val
      end
    end
    nil
  end

  # Print the contents of the table
  #
  # NOTE: Used for debugging
  def print_table
    @table.each do |e|
      unless e.nil?
        puts e
      end
    end
  end
end
