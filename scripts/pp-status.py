import sys
import commands

name = sys.argv[1]
cmd = "dmsetup status %s" % name
output = commands.getoutput(cmd)

xs = output.split()

t1 = "\
nr_dirties: %d\n\
nr_segmentes: %d\n\
last migrated id: %d\n\
last flushd id: %d\n\
cur seg id: %d\n\
pos cursor: %d\n\
write? hit? buffer? fullsize?\n\
" % (int(xs[3]), int(xs[4]), int(xs[5]), int(xs[6]), int(xs[7]), int(xs[8])) 

stats = [xs[9+i] for i in range(0,16)]
types = [(a, b, c, d) for d in range(0,2) for c in range(0,2) for b in range(0,2) for a in range(0,2)]

t2 = "\n".join(["%d %d %d %d %d" % (int(a), int(b), int(c), int(d), int(e)) for ((a, b, c, d), e) in zip(types, stats)]) + "\n"
aaa = xs[26:]
t3 = "\n".join(["%s: %d" % (a, int(b)) for a, b in zip(aaa[0::2], aaa[1::2])])

t = t1 + t2 + t3
print(t)
