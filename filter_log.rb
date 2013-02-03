OK_WORDS = [
  "warning: ISO C90 forbids mixed declarations and code",
]

def match(line)
  OK_WORDS.each do |word|
    return true if line.include? word
  end
  false
end

if __FILE__ == $0
  input = ARGV[0]

  arr = []
  `cat #{input} | grep warning`.split("\n").each do |line|
    if match(line)
      next
    end
    arr << line
  end
  $stdout << arr.join("\n")
end
