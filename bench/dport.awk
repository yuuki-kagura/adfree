# Renders the two halves of one tunnelled connection from /proc/net/tcp.
#   -v bp=<hex local port> : the client sockets pinned to that port
#   app>...  an engine (uid 10344) socket whose peer is port 80: a relay that dialed
#   cli[...] a helper (uid 10309) socket on the bound port: the client half
BEGIN {
  est["01"] = "EST"; est["02"] = "SYN-SENT"; est["03"] = "SYN-RECV";
  est["04"] = "FIN-WAIT"; est["05"] = "TIME-WAIT"; est["06"] = "TIME-WAIT";
  est["07"] = "CLOSE-WAIT"; est["08"] = "LAST-ACK"; est["09"] = "LISTEN";
  est["0a"] = "CLOSE"; est["0b"] = "CLOSING";
}
{
  split($3, r, ":"); split($2, l, ":");
  s = ($4 in est) ? est[$4] : $4;
  if ($8 == "10344" && r[2] == "0050") a = a " app>" l[1] ":" strtonum("0x" l[2]) "->" r[1] ":" strtonum("0x" r[2]) " " s;
  if ($8 == "10309" && l[2] == bp)     c = c " cli[" l[1] ":" strtonum("0x" l[2]) "->" r[1] ":" strtonum("0x" r[2]) "] " s;
}
END { print a " |" c }
