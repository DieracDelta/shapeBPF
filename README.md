# what is this

Typically bandwidth shaping happens via qdiscs that you add with tc. Or I guess syscalls if you're down with manually doing tcs work for it.

My biggest issues with this are they aren't nix enough. You can AFAIU create firewall rules, but not impose your will declaratively for bandwidth.


This project does exactly that. I prove a TUI where the user can add bandwidth shaping rules directly via the TUI and directly run them as a BPF program.
Note that typically bandwidth shaping is only done via qdiscs on output packets. And typically if the output packets are delayed, the input packets will slow down too.

But, I wanted something more aggressive. So in addition to qdiscs to limit upload, I allow for the bpf program to limit downloads. It will literally drop packets for a cgroup/process/etc.

I also allow for the user to "isolate" a bandwidth hungry process into a separate cgroup where we can more aggressively limit bandwidth. Basically, ephemeral cgroups.


# disclaimer: here be AI

I iterated with claude to build this.
