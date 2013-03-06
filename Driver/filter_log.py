import sys 

OK_WORDS = [
	"In function",		
	"ISO C90 forbids mixed declarations",
]

def do_filter(lines):
	_lines = []
	for line in lines:
		b = True
		for w in OK_WORDS:
			b &= not (w in line)
		if(b):
			_lines.append(line)
	return _lines	

if __name__ == '__main__':
	filename = sys.argv[1]
	lines = open(filename, 'r').read().split("\n")
	s = '\n'.join(do_filter(lines)).strip()
	print(s)
