from ebpfcat.arraymap import ArrayMap as ma
from ebpfcat.xdp import XDP as xdp, XDPExitCode, XDPFlags, PacketVar as pv
from ebpfcat.ebpf import ktime as kt

from readchar import readchar as rc

from asyncio import get_event_loop as gel, sleep as s, wait_for as wf

ps=XDPExitCode.PASS
tx=XDPExitCode.TX

class rok(xdp):
	license = "GPL"
	
	m = ma()
	t0=m.globalVar("Q")
	td=m.globalVar("Q")
	f=m.globalVar("B")
	v1=m.globalVar("B")
	v11=m.globalVar("B")
	v2=m.globalVar("H")
	v4=m.globalVar("I")
	pv1=pv(0,"!B")

	def program(s):
		with kt(s).calculate(None,1,1) as (kt0,_):	s.t0 = s.r[kt0]
		with s.packetSize>=43 as pt:
			s.v1=pt.pB[42]
		
		with kt(s).calculate(None,1,1) as (kt0,_):	s.td = s.r[kt0] - s.t0
		s.exit(ps)

async def m():
	c0=rok()
	await c0.attach("eth0", XDPFlags.DRV_MODE)
	while 1:
		match rc():
			case "q":
				print("Detaching...")
				a = c0.detach("eth0", XDPFlags.DRV_MODE)
				await wf(a,1)
				print(f"Detaching timeout. But it is likely detached.")
				return
			case _:	print(f"dump:\t v1:{c0.v1}")

if __name__=="__main__":
	gel().run_until_complete(m())