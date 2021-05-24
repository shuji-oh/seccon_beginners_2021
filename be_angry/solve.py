import angr

p = angr.Project("./chall")
state = p.factory.entry_state()
sim = p.factory.simulation_manager(state)
sim.explore(find=(0x400000+0x2031,), avoid=(0x400000+0x1963,))
if len(sim.found) > 0:
        print(sim.found[0].posix.dumps(0))


'''
    1378:	e8 f3 fc ff ff       	call   1070 <puts@plt>
    1435:	e8 36 fc ff ff       	call   1070 <puts@plt>
    1451:	e8 1a fc ff ff       	call   1070 <puts@plt>
    14d3:	e8 98 fb ff ff       	call   1070 <puts@plt>
    192b:	e8 40 f7 ff ff       	call   1070 <puts@plt>
    1947:	e8 24 f7 ff ff       	call   1070 <puts@plt>
    1a1e:	e8 4d f6 ff ff       	call   1070 <puts@plt>
    1a3a:	e8 31 f6 ff ff       	call   1070 <puts@plt>
    1b3b:	e8 30 f5 ff ff       	call   1070 <puts@plt>
    1df0:	e8 7b f2 ff ff       	call   1070 <puts@plt>
    1e0c:	e8 5f f2 ff ff       	call   1070 <puts@plt>
    1e28:	e8 43 f2 ff ff       	call   1070 <puts@plt>
    1eb4:	e8 b7 f1 ff ff       	call   1070 <puts@plt>
    1f78:	e8 f3 f0 ff ff       	call   1070 <puts@plt>
    1ff9:	e8 72 f0 ff ff       	call   1070 <puts@plt>
    2015:	e8 56 f0 ff ff       	call   1070 <puts@plt>
    2031:	e8 3a f0 ff ff       	call   1070 <puts@plt>
    251d:	e8 4e eb ff ff       	call   1070 <puts@plt>
    2539:	e8 32 eb ff ff       	call   1070 <puts@plt>
    2555:	e8 16 eb ff ff       	call   1070 <puts@plt>
    2571:	e8 fa ea ff ff       	call   1070 <puts@plt>
    258d:	e8 de ea ff ff       	call   1070 <puts@plt>
    2653:	e8 18 ea ff ff       	call   1070 <puts@plt>
    26c4:	e8 a7 e9 ff ff       	call   1070 <puts@plt>

flag:ctf4b{3nc0d3_4r1thm3t1
'''