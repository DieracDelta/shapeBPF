{ pkgs, shapebpfModule }:

pkgs.testers.runNixOSTest {
  name = "shapebpf-priority";

  nodes = {
    server = { config, pkgs, ... }: {
      boot.kernelPackages = pkgs.linuxPackages_latest;
      networking.firewall.allowedTCPPorts = [ 5201 5202 ];
      environment.systemPackages = [ pkgs.iperf3 ];
    };

    client = { config, pkgs, ... }: {
      imports = [ shapebpfModule ];
      boot.kernelPackages = pkgs.linuxPackages_latest;

      services.shapebpf = {
        enable = true;
        interface = "eth1";
        defaultRule = {
          egressRateBps = 1048576;  # 1 MB/s safety net for unclassified traffic
          priority = 5;
        };
        rules = [
          {
            name = "high-priority";
            serviceUnit = "iperf3-hi.service";
            priority = 1;
            # No egressRateBps → 0 → no EDT pacing
          }
          {
            name = "low-priority";
            serviceUnit = "iperf3-lo.service";
            priority = 10;
          }
        ];
      };

      environment.systemPackages = [ pkgs.iperf3 ];
    };
  };

  testScript = ''
    start_all()

    server.wait_for_unit("network.target")
    client.wait_for_unit("network.target")

    server.succeed("iperf3 -s -p 5201 -D")
    server.succeed("iperf3 -s -p 5202 -D")

    client.wait_for_unit("shapebpf.service")
    client.sleep(3)

    # Launch both in separate systemd units (separate cgroups)
    client.succeed(
        "systemd-run --unit=iperf3-hi "
        "--property=StandardOutput=file:/tmp/hi.json "
        "-- iperf3 -c server -p 5201 -t 15 -J"
    )
    client.succeed(
        "systemd-run --unit=iperf3-lo "
        "--property=StandardOutput=file:/tmp/lo.json "
        "-- iperf3 -c server -p 5202 -t 15 -J"
    )

    # Wait for iperf3 to finish (15s test + buffer)
    client.wait_until_succeeds("test -s /tmp/hi.json && test -s /tmp/lo.json", timeout=30)

    import json

    hi = json.loads(client.succeed("cat /tmp/hi.json"))
    lo = json.loads(client.succeed("cat /tmp/lo.json"))

    hi_bps = hi["end"]["sum_sent"]["bits_per_second"]
    lo_bps = lo["end"]["sum_sent"]["bits_per_second"]

    print(f"High priority: {hi_bps/1e6:.2f} Mbps")
    print(f"Low priority:  {lo_bps/1e6:.2f} Mbps")

    # Kernel version check (sch_bpf requires 6.16+)
    kernel_ver = client.succeed("uname -r").strip()
    parts = kernel_ver.split(".")
    major, minor = int(parts[0]), int(parts[1])

    if major > 6 or (major == 6 and minor >= 16):
        assert hi_bps > lo_bps, (
            f"High priority ({hi_bps/1e6:.2f} Mbps) should exceed "
            f"low priority ({lo_bps/1e6:.2f} Mbps)"
        )
        print("PASS: Priority queuing is active")
    else:
        print(f"SKIP: Kernel {kernel_ver} < 6.16, sch_bpf not available")
        assert hi_bps > 0 and lo_bps > 0, "No bandwidth measured"
        print("PASS: Monitor-only mode working correctly")

    client.succeed("systemctl is-active shapebpf.service")
  '';
}
