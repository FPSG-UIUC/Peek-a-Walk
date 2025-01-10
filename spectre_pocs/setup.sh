#!/bin/bash
# sudo mount -t tmpfs cgroup_root /sys/fs/cgroup
# mkdir /sys/fs/cgroup/cpu
# sudo mount -t cgroup cpu -o cpu /sys/fs/cgroup/cpu/
mkdir /sys/fs/cgroup/user.slice2
sudo mount -t cgroup user.slice -o cpu /sys/fs/cgroup/user.slice2/
