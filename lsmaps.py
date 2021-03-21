import os
import re

# print only short library name
printShort = True
# do not include this process in aggregation
omitSelf = False


class Maps:
    def __init__(self, name, vmem):
        self.name = name
        self.vmem = vmem

'''
Parse shared libraries from /proc/<pid>/maps passed content.
Aggregate size of so_vmarea used by shared library mapping. 
Return a list matched libraries in Maps object.

Input format as described in man page PROC[5] (without head-line):
    address           perms offset  dev   inode       pathname
    00400000-00452000 r-xp 00000000 08:02 173521      /usr/bin/dbus-daemon
    00651000-00652000 r--p 00051000 08:02 173521      /usr/bin/dbus-daemon
    00652000-00655000 rw-p 00052000 08:02 173521      /usr/bin/dbus-daemon
    00e03000-00e24000 rw-p 00000000 00:00 0           [heap]
    00e24000-011f7000 rw-p 00000000 00:00 0           [heap]
    ...
    35b1800000-35b1820000 r-xp 00000000 08:02 135522  /usr/lib64/ld-2.15.so
    35b1a1f000-35b1a20000 r--p 0001f000 08:02 135522  /usr/lib64/ld-2.15.so
    35b1a20000-35b1a21000 rw-p 00020000 08:02 135522  /usr/lib64/ld-2.15.so
    35b1a21000-35b1a22000 rw-p 00000000 00:00 0
    35b1c00000-35b1dac000 r-xp 00000000 08:02 135870  /usr/lib64/libc-2.15.so
    35b1dac000-35b1fac000 ---p 001ac000 08:02 135870  /usr/lib64/libc-2.15.so
    35b1fac000-35b1fb0000 r--p 001ac000 08:02 135870  /usr/lib64/libc-2.15.so
    35b1fb0000-35b1fb2000 rw-p 001b0000 08:02 135870  /usr/lib64/libc-2.15.so
    ...
    f2c6ff8c000-7f2c7078c000 rw-p 00000000 00:00 0    [stack:986]
    ...
    7fffb2c0d000-7fffb2c2e000 rw-p 00000000 00:00 0   [stack]
    7fffb2d48000-7fffb2d49000 r-xp 00000000 00:00 0   [vdso]

'''
def parse_maps(maps):
    maps_objs = []
    l = {}

    matches = re.findall(r".*\/.*\.so.*", maps)
    for match in matches:
        so_vmarea = re.findall(r"\/.*\.so.*", match)[0]
        start_addr, end_addr = re.findall(r"[\da-fA-F]+", match)[0:2]
        vmem = int(end_addr, 16) - int(start_addr, 16)
        # Aggregate vmareas' size
        if so_vmarea not in l:
            l[so_vmarea] = vmem
        else:
            l[so_vmarea] += vmem
    
    for r in l.keys():
        maps_objs.append(Maps(r, l[r]))
    
    return maps_objs

'''
Get flags from /proc/<pid>/stat

Input format as described in man page PROC[5]:
    (9) flags  %u
        The kernel flags word of the process.  For bit
        meanings, see the PF_* defines in the Linux kernel
        source file include/linux/sched.h.  Details depend
        on the kernel version.
    ...
...
'''
def get_stat_flags(stat):
    stat = stat[stat.find(')'):-1]
    if len(stat) > 0:
        stat_fields = stat.split(' ')
        if len(stat_fields) >= 8:
            return int(stat_fields[7])
    return -1

'''
Thread flags in include/linux/sched.h:

#define PF_EXITING		0x00000004	/* Getting shut down */
#define PF_KTHREAD		0x00200000	/* I am a kernel thread */
...
'''
def is_running_uthread(flags):
    return not ((flags & 0x200000) or (flags & 0x4))

'''
Read the contents of given VFS path.
'''
def read_file(vfs_path):
    try:
        f_handle = open(vfs_path, 'r')
        content = f_handle.read()
        f_handle.close()
        return content
    except IOError as e:
        return ""

'''
Walk over /proc/<pid>/maps and aggregate stats on shared libraries.
'''
def walk_proc_maps():
    maps_count = 0 # number of parsed maps
    p_maps = {} # pid -> Maps
    lib_count = {} # .so-name -> [map-count, vmem-size]

    for (root, dirs, files) in os.walk('/proc/'):
        # Include only /proc/<pid> paths
        dirs[:] = [d for d in dirs if re.match(r"\d+", d)]
        for d in dirs:
            # Exclude pid without maps - exiting threads, kthreads
            stats_path = os.path.join(root, d, 'stat')
            flags = get_stat_flags(read_file(stats_path))
            if flags < 0 or not is_running_uthread(flags):
                continue
            # Optionally, exclude self python instance
            if omitSelf and int(d) == os.getpid():
                continue
            maps_count += 1

            # Parse maps of current pid
            maps_path = os.path.join(root, d, 'maps')
            p_map = parse_maps(read_file(maps_path))
            if len(p_map) > 0:
                p_maps[d] = p_map
                for map_obj in p_maps[d]:
                    if map_obj.name not in lib_count:
                        lib_count[map_obj.name] = [1, map_obj.vmem]
                    else:
                        lib_count[map_obj.name][0] += 1

    # Sort after map-count
    lib_count_sorted = sorted(lib_count.items(), key=lambda x: x[1][0], reverse=True)

    print("[UID %d] #User-process maps scanned %d" % (os.getuid(), len(p_maps)))
    print("#Total user-process maps %d" % (maps_count))
    print("#Shared libraries loaded %d" % len(lib_count))
    print("<library, map-count, vmem-size>")
    for i in lib_count_sorted:
        lib_map = i[1]
        head, lib_name = os.path.split(i[0])
        vmem = int(lib_map[1] / 1000)
        if printShort:
            print ('{:40s} {:3d} {:10d}K'.format(lib_name, lib_map[0], vmem))
        else:
            print ('{:80s} {:3d} {:10d}K'.format(i[0], lib_map[0], vmem))

if __name__ == '__main__':
    walk_proc_maps()
